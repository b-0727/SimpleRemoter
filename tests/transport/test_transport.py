import asyncio
import base64
import hashlib
import os
import secrets
import ssl
import struct
from dataclasses import dataclass
from typing import Awaitable

import pytest

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - optional dependency for AES-GCM checks
    AESGCM = None


# -------------------- Length-prefixed framing helpers --------------------

def encode_length_prefixed(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


async def read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    length_raw = await reader.readexactly(4)
    (length,) = struct.unpack("!I", length_raw)
    data = await reader.readexactly(length)
    return data


async def write_fragmented(writer: asyncio.StreamWriter, payload: bytes, *, chunk_size: int = 32) -> None:
    view = memoryview(payload)
    idx = 0
    while idx < len(view):
        step = min(len(view) - idx, secrets.randbelow(chunk_size) + 1)
        writer.write(view[idx: idx + step])
        await writer.drain()
        idx += step


# -------------------- Minimal WebSocket framing --------------------

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
REQUIRED_PROTOCOL = "sr-auth-token"
ALLOWED_ORIGIN = "https://allowed.example"


@dataclass
class WSFrame:
    opcode: int
    payload: bytes
    fin: bool = True
    masked: bool = False


SEEN_CLIENT_NONCES: set[str] = set()


def parse_headers(block: bytes) -> dict[str, str]:
    lines = block.decode().split("\r\n")
    hdrs: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            name, value = line.split(":", 1)
            hdrs[name.strip().lower()] = value.strip()
    return hdrs


async def websocket_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    server_side: bool,
    protocol: str = REQUIRED_PROTOCOL,
    origin: str = ALLOWED_ORIGIN,
    client_nonce: bytes | None = None,
    seen_nonces: set[str] | None = None,
) -> str | None:
    if server_side:
        request = await reader.readuntil(b"\r\n\r\n")
        headers = parse_headers(request)
        key_line = headers.get("sec-websocket-key")
        if not key_line:
            raise RuntimeError("Missing Sec-WebSocket-Key")
        key = key_line.strip()
        if protocol and headers.get("sec-websocket-protocol") != protocol:
            raise RuntimeError("Missing or mismatched protocol")
        if origin and headers.get("origin") != origin:
            raise RuntimeError("Origin rejected")
        if client_nonce is None:
            client_nonce = bytes.fromhex(headers.get("x-sr-client-nonce", "")) if headers.get("x-sr-client-nonce") else b""
        if seen_nonces is not None:
            nonce_hex = headers.get("x-sr-client-nonce", "")
            if nonce_hex in seen_nonces:
                raise RuntimeError("Replay nonce seen")
            seen_nonces.add(nonce_hex)
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n"
            f"X-SR-Server-Nonce: {os.urandom(16).hex()}\r\n\r\n"
        )
        writer.write(response.encode())
        await writer.drain()
    else:
        key = base64.b64encode(os.urandom(16)).decode()
        nonce_hex = (client_nonce or os.urandom(16)).hex()
        handshake = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n"
            f"Origin: {origin}\r\n"
            f"X-SR-Client-Nonce: {nonce_hex}\r\n\r\n"
        )
        writer.write(handshake.encode())
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        if b"101" not in response:
            raise RuntimeError(f"Handshake failed: {response!r}")
        return nonce_hex


def encode_ws_frame(frame: WSFrame) -> bytes:
    payload = frame.payload
    header = bytearray()
    header.append((0x80 if frame.fin else 0) | (frame.opcode & 0x0F))
    mask_bit = 0x80 if frame.masked else 0
    length = len(payload)
    if length < 126:
        header.append(mask_bit | length)
    elif length < (1 << 16):
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))

    if frame.masked:
        mask_key = os.urandom(4)
        header.extend(mask_key)
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return bytes(header) + payload


async def read_ws_frame(reader: asyncio.StreamReader, *, expect_masked: bool) -> WSFrame:
    head = await reader.readexactly(2)
    b1, b2 = head
    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    if expect_masked and not masked:
        raise ValueError("Expected masked frame from peer")
    length = b2 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", await reader.readexactly(2))
    elif length == 127:
        (length,) = struct.unpack("!Q", await reader.readexactly(8))
    mask_key = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return WSFrame(opcode=opcode, payload=payload, fin=fin, masked=masked)


# -------------------- Servers --------------------

async def tcp_echo_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            payload = await read_length_prefixed(reader)
            await write_fragmented(writer, encode_length_prefixed(payload))
    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def wss_gateway(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await websocket_handshake(reader, writer, server_side=True, seen_nonces=SEEN_CLIENT_NONCES)
        while True:
            frame = await read_ws_frame(reader, expect_masked=True)
            if frame.opcode == 0x8:  # Close
                break
            writer.write(encode_ws_frame(WSFrame(opcode=0x2, payload=frame.payload, fin=True, masked=False)))
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
        pass
    finally:
        try:
            writer.write(encode_ws_frame(WSFrame(opcode=0x8, payload=b"", fin=True, masked=False)))
            await writer.drain()
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()


# -------------------- Test helpers --------------------

@dataclass
class TransportHarness:
    port: int
    server: asyncio.AbstractServer
    ssl_context: ssl.SSLContext | None = None

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()


async def start_tcp_harness() -> TransportHarness:
    server = await asyncio.start_server(tcp_echo_server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return TransportHarness(port=port, server=server)


async def start_wss_harness(cert_path: str, key_path: str) -> TransportHarness:
    SEEN_CLIENT_NONCES.clear()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server = await asyncio.start_server(wss_gateway, "127.0.0.1", 0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]
    return TransportHarness(port=port, server=server, ssl_context=ssl_ctx)


async def tcp_client_roundtrip(port: int, payloads: list[bytes]) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for payload in payloads:
        await write_fragmented(writer, encode_length_prefixed(payload))
        echoed = await read_length_prefixed(reader)
        assert echoed == payload
    writer.close()
    await writer.wait_closed()


async def wss_client_roundtrip(port: int, payloads: list[bytes], *, ssl_ctx: ssl.SSLContext) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ssl_ctx)
    await websocket_handshake(reader, writer, server_side=False)
    for payload in payloads:
        frame = WSFrame(opcode=0x2, payload=payload, fin=True, masked=True)
        await write_fragmented(writer, encode_ws_frame(frame))
        echo = await read_ws_frame(reader, expect_masked=False)
        assert echo.payload == payload
    writer.write(encode_ws_frame(WSFrame(opcode=0x8, payload=b"", fin=True, masked=True)))
    await writer.drain()
    writer.close()
    await writer.wait_closed()


# -------------------- Tests --------------------


def run(coro: Awaitable[None]):
    return asyncio.run(coro)


def test_tcp_round_trip_randomized_fragmentation():
    async def scenario():
        harness = await start_tcp_harness()
        payloads = [os.urandom(secrets.randbelow(1024) + 1) for _ in range(10)]
        try:
            await tcp_client_roundtrip(harness.port, payloads)
        finally:
            await harness.stop()
    run(scenario())


def test_wss_round_trip_randomized_fragmentation(tmp_path):
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        payloads = [os.urandom(secrets.randbelow(1024) + 1) for _ in range(10)]
        try:
            await wss_client_roundtrip(harness.port, payloads, ssl_ctx=client_ctx)
        finally:
            await harness.stop()
    run(scenario())


def test_wss_handshake_rejects_bad_protocol(tmp_path):
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port, ssl=client_ctx)
        try:
            with pytest.raises((asyncio.IncompleteReadError, RuntimeError)):
                await websocket_handshake(reader, writer, server_side=False, protocol="bad-token")
        finally:
            writer.close()
            await writer.wait_closed()
            await harness.stop()

    run(scenario())


def test_wss_replay_nonce_rejected(tmp_path):
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")
    replay_nonce = os.urandom(16)

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        async def connect_once(expect_success: bool) -> None:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port, ssl=client_ctx)
            try:
                if expect_success:
                    await websocket_handshake(reader, writer, server_side=False, client_nonce=replay_nonce)
                else:
                    with pytest.raises((asyncio.IncompleteReadError, RuntimeError, ConnectionResetError)):
                        await websocket_handshake(reader, writer, server_side=False, client_nonce=replay_nonce)
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            await connect_once(expect_success=True)
            await connect_once(expect_success=False)
        finally:
            await harness.stop()

    run(scenario())


def test_aes_gcm_consistency_over_transports():
    if AESGCM is None:
        pytest.skip("cryptography is required for AES-GCM regression checks")

    key = AESGCM.generate_key(bit_length=128)
    aes = AESGCM(key)
    payloads = [os.urandom(256) for _ in range(3)]
    messages = [(nonce := os.urandom(12), aes.encrypt(nonce, payload, None)) for payload in payloads]

    async def scenario():
        tcp = await start_tcp_harness()
        wss = await start_wss_harness(
            os.path.join(os.path.dirname(__file__), "certs", "server.crt"),
            os.path.join(os.path.dirname(__file__), "certs", "server.key"),
        )
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        async def decrypt_over_tcp():
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp.port)
            try:
                for nonce, ciphertext in messages:
                    await write_fragmented(writer, encode_length_prefixed(nonce + ciphertext))
                    echoed = await read_length_prefixed(reader)
                    r_nonce, r_cipher = echoed[:12], echoed[12:]
                    assert aes.decrypt(r_nonce, r_cipher, None) in payloads
            finally:
                writer.close()
                await writer.wait_closed()

        async def decrypt_over_wss():
            reader, writer = await asyncio.open_connection("127.0.0.1", wss.port, ssl=client_ctx)
            await websocket_handshake(reader, writer, server_side=False)
            try:
                for nonce, ciphertext in messages:
                    frame = WSFrame(opcode=0x2, payload=nonce + ciphertext, fin=True, masked=True)
                    await write_fragmented(writer, encode_ws_frame(frame))
                    echoed = await read_ws_frame(reader, expect_masked=False)
                    r_nonce, r_cipher = echoed.payload[:12], echoed.payload[12:]
                    assert aes.decrypt(r_nonce, r_cipher, None) in payloads
            finally:
                writer.write(encode_ws_frame(WSFrame(opcode=0x8, payload=b"", fin=True, masked=True)))
                await writer.drain()
                writer.close()
                await writer.wait_closed()

        try:
            await asyncio.gather(decrypt_over_tcp(), decrypt_over_wss())
        finally:
            await tcp.stop()
            await wss.stop()


def test_wss_rejects_bad_origin_and_recovers():
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        async def attempt_with_bad_origin():
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port, ssl=client_ctx)
            try:
                with pytest.raises((asyncio.IncompleteReadError, RuntimeError)):
                    await websocket_handshake(
                        reader,
                        writer,
                        server_side=False,
                        origin="https://untrusted.example",
                    )
            finally:
                writer.close()
                await writer.wait_closed()

        async def healthy_round_trip():
            payloads = [os.urandom(secrets.randbelow(2048) + 512) for _ in range(4)]
            await wss_client_roundtrip(harness.port, payloads, ssl_ctx=client_ctx)

        try:
            await attempt_with_bad_origin()
            await healthy_round_trip()
        finally:
            await harness.stop()

    run(scenario())


def test_parallel_tcp_and_wss_clients():
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        tcp_harness = await start_tcp_harness()
        wss_harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        tcp_payloads = [[os.urandom(secrets.randbelow(512) + 1) for _ in range(5)] for _ in range(3)]
        wss_payloads = [[os.urandom(secrets.randbelow(512) + 1) for _ in range(5)] for _ in range(3)]

        tcp_clients = [tcp_client_roundtrip(tcp_harness.port, payloads) for payloads in tcp_payloads]
        wss_clients = [wss_client_roundtrip(wss_harness.port, payloads, ssl_ctx=client_ctx) for payloads in wss_payloads]

        try:
            await asyncio.wait_for(asyncio.gather(*tcp_clients, *wss_clients), timeout=10)
        finally:
            await tcp_harness.stop()
            await wss_harness.stop()

    run(scenario())


def test_unmasked_client_frame_triggers_close():
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port, ssl=client_ctx)
        await websocket_handshake(reader, writer, server_side=False)
        writer.write(encode_ws_frame(WSFrame(opcode=0x2, payload=b"oops", fin=True, masked=False)))
        await writer.drain()

        frame = await read_ws_frame(reader, expect_masked=False)
        assert frame.opcode == 0x8

        writer.close()
        await writer.wait_closed()
        await harness.stop()

    run(scenario())


def test_negative_corrupted_frame_and_truncated_ciphertext():
    if AESGCM is None:
        pytest.skip("cryptography is required for AES-GCM regression checks")

    key = AESGCM.generate_key(bit_length=128)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    good_cipher = aes.encrypt(nonce, b"payload", None)

    async def scenario():
        harness = await start_tcp_harness()
        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
        try:
            # Corrupted length (claims longer than data) should close the connection cleanly
            writer.write(struct.pack("!I", len(good_cipher) + 10))
            writer.write(good_cipher)
            await writer.drain()
            # Close the writer so the server observes EOF instead of blocking forever
            writer.close()
            await writer.wait_closed()
            with pytest.raises(asyncio.IncompleteReadError):
                await read_length_prefixed(reader)
        finally:
            await harness.stop()

    run(scenario())


def test_negative_incorrect_mask_and_abrupt_close():
    cert = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    key = os.path.join(os.path.dirname(__file__), "certs", "server.key")

    async def scenario():
        harness = await start_wss_harness(cert, key)
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection("127.0.0.1", harness.port, ssl=client_ctx)
        await websocket_handshake(reader, writer, server_side=False)
        try:
            # Send unmasked binary frame; server should drop connection
            bad_frame = encode_ws_frame(WSFrame(opcode=0x2, payload=b"oops", fin=True, masked=False))
            writer.write(bad_frame)
            await writer.drain()
            close_frame = await read_ws_frame(reader, expect_masked=False)
            assert close_frame.opcode == 0x8
        finally:
            try:
                writer.write(encode_ws_frame(WSFrame(opcode=0x8, payload=b"", fin=True, masked=True)))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()
            await harness.stop()

    run(scenario())


def test_handshake_replay_nonce_rejected():
    async def scenario():
        seen: set[str] = set()
        outcomes: list[str] = []

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                await websocket_handshake(reader, writer, server_side=True, seen_nonces=seen)
                outcomes.append("accepted")
            except RuntimeError:
                outcomes.append("replayed")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def dial_once(client_nonce: bytes):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await websocket_handshake(reader, writer, server_side=False, client_nonce=client_nonce)
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()

        nonce = os.urandom(16)
        await dial_once(nonce)
        await dial_once(nonce)

        server.close()
        await server.wait_closed()

        assert outcomes == ["accepted", "replayed"]

    run(scenario())

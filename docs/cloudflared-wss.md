# Cloudflare Quick Tunnel (WSS) Integration Plan

This document describes how to expose SimpleRemoter over Cloudflare Quick Tunnels by adding a WebSocket (WSS) transport layer while preserving the existing AES-GCM security pipeline and module interfaces.

## Goals

- Terminate TLS at Cloudflare and tunnel WSS traffic from a public hostname to a local WebSocket listener.
- Translate WebSocket frames to the current raw TCP transport without altering the packet format or AEAD encryption. A shared framer in `common/websocket_frame.*` unwraps masked frames, enforces payload caps, and feeds the raw bytes into the existing `HeaderParser`/`PkgMask` pipeline.
- Keep modules unchanged while enabling both TCP and WSS modes.
- Provide clear configuration guidance for operators.

## Architecture Changes

### WSS Gateway (Server)

- Add a lightweight WebSocket listener (separate port, e.g., 24443) that performs the HTTP Upgrade handshake and unwraps WebSocket binary frames.
- Forward the resulting byte stream into the existing IOCP TCP pipeline (reusing `HeaderParser`/`PkgMask` and AES-GCM handling).
- Wrap outbound packets from the server back into WebSocket binary frames before sending to the client via the tunnel.
- Run the gateway locally; Cloudflared forwards `wss://<hostname>` to this port.

### WebSocket Client Transport

- Provide a WebSocket-based client transport alongside the current TCP socket implementation.
- Reuse the existing packet serializer and AES-GCM routines; only the underlying send/receive functions change to frame/unframe WebSocket messages.
- Allow selection between TCP and WSS via configuration (CLI flag or build-time option) and accept a Cloudflare-issued hostname/port.

### UDP/KCP Considerations

- Quick Tunnels only forward TCP/WebSocket traffic; UDP-dependent features (e.g., KCP, raw UDP streams) must be gated.
- Introduce a capability flag to disable or reroute UDP/KCP modules when WSS is selected, using the existing TCP path as the fallback.

## Security

- Preserve the current AES-GCM (AEAD) encryption and nonce handling end-to-end; the WebSocket layer only carries encrypted payloads.
- Maintain the existing session key derivation logic. If a pre-shared key is used, derive per-session keys before upgrading to WebSocket.
- Keep module authentication/authorization unchanged.

## Cloudflared Setup

1. Install `cloudflared` and authenticate (`cloudflared tunnel login`).
2. Run a Quick Tunnel that forwards to the local WSS gateway port:
   ```bash
   cloudflared tunnel --url http://localhost:24443
   ```
   Cloudflare outputs a temporary hostname (e.g., `https://example.trycloudflare.com`).
3. Configure the SimpleRemoter client to connect via `wss://example.trycloudflare.com` using the WebSocket transport.
4. Add a 32-byte hex `wss_key` to the client's `settings` section (read from `client/remote.ini`) and mirror the same value as `encryption_key` in `server/gateway.ini`. The gateway will refuse to start if the key is not exactly 32 bytes so every payload stays wrapped in AES-256-GCM even when TLS terminates at Cloudflare.

## Operational Notes

- Prefer WebSocket binary frames; avoid per-message masking server-side because Cloudflare already handles TLS termination.
- Keep frame sizes modest for high-bandwidth modules (remote desktop/audio); buffer and chunk large payloads to reduce latency spikes.
- Document any limitations for operators (e.g., "UDP features disabled under WSS").

## Follow-up Work Items

- Implement the WebSocket gateway and client transport wrappers.
- Add configuration surfaces (UI/CLI) for selecting TCP vs WSS and supplying the Cloudflare hostname/port.
- Gate UDP/KCP modules behind a transport capability check.
- Add regression tests for WebSocket framing/unframing and AES-GCM integrity across both transports. See `tests/websocket_frame_tests.cpp` for negative-path coverage (masked frames, oversize payloads, truncation) and reconnect-friendly framing validation.

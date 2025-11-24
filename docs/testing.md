# Transport Test Harness

This repository now includes a Python test harness that validates both the raw TCP transport and the mock WSS gateway used for framing/unframing and AES-GCM payload handling.

## Prerequisites

Install the Python test dependencies (Python 3.10+ recommended). The AES-GCM checks rely on `cryptography`; if it is not availab
le locally, those cases will be reported as skipped.

```bash
pip install -r requirements-dev.txt
```

## Running the Suite

Execute the transport regression suite with `pytest`:

```bash
python -m pytest tests/transport
```

The suite will:

- Spin up an in-process TCP echo server and a TLS-wrapped mock WSS gateway on loopback.
- Exercise randomized payload sizes with deliberate fragmentation to verify bidirectional framing and unframing.
- Perform AES-GCM round trips over both transports to confirm nonce handling and tag verification are preserved.
- Cover negative paths (corrupted frames, truncated ciphertext, incorrect masks, and abrupt close frames) to assert graceful teardown on both the client and gateway sides.

All servers run locally and clean up automatically after the tests finish.

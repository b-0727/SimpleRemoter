#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct WebSocketFrame
{
    bool fin;
    bool masked;
    uint8_t opcode;
    std::vector<uint8_t> payload;
};

// Build a simple binary WebSocket frame. When mask is true, RFC6455 masking is applied.
std::vector<uint8_t> BuildWebSocketFrame(const std::vector<uint8_t>& payload, bool mask = false, uint8_t opcode = 0x2);

// Parse a WebSocket frame from a contiguous buffer. Returns false on malformed input
// (unsupported control bits, masked server frames, payload too large, etc.).
bool ParseWebSocketFrame(const std::vector<uint8_t>& buffer, WebSocketFrame& out, size_t maxPayload = 1 << 20, std::string* error = nullptr);

// Convenience helpers for negative-path testing.
bool IsFrameTooLarge(const std::vector<uint8_t>& buffer, size_t maxPayload);
bool IsFrameMasked(const std::vector<uint8_t>& buffer);

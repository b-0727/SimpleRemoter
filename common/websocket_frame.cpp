#include "websocket_frame.h"
#include <random>
#include <stdexcept>

namespace {
uint32_t random_mask()
{
    static std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFFu);
    return dist(rng);
}
}

std::vector<uint8_t> BuildWebSocketFrame(const std::vector<uint8_t>& payload, bool mask, uint8_t opcode)
{
    std::vector<uint8_t> frame;
    frame.reserve(payload.size() + 10);
    uint8_t first = 0x80 | (opcode & 0x0F);
    frame.push_back(first);

    uint8_t maskBit = mask ? 0x80 : 0;
    if (payload.size() < 126) {
        frame.push_back(maskBit | static_cast<uint8_t>(payload.size()));
    } else if (payload.size() <= 0xFFFF) {
        frame.push_back(maskBit | 126);
        uint16_t len = static_cast<uint16_t>(payload.size());
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(maskBit | 127);
        uint64_t len = payload.size();
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }
    }

    uint32_t maskKey = mask ? random_mask() : 0;
    if (mask) {
        for (int i = 3; i >= 0; --i) {
            frame.push_back(static_cast<uint8_t>((maskKey >> (i * 8)) & 0xFF));
        }
    }

    for (size_t i = 0; i < payload.size(); ++i) {
        uint8_t byte = payload[i];
        if (mask) {
            byte ^= reinterpret_cast<uint8_t*>(&maskKey)[i % 4];
        }
        frame.push_back(byte);
    }

    return frame;
}

static bool parse_length(const std::vector<uint8_t>& buffer, size_t& offset, uint64_t& payloadLen)
{
    if (offset >= buffer.size()) return false;
    uint8_t lenByte = buffer[offset++];
    bool masked = (lenByte & 0x80) != 0;
    uint8_t lenIndicator = (lenByte & 0x7F);
    if (lenIndicator < 126) {
        payloadLen = lenIndicator;
    } else if (lenIndicator == 126) {
        if (offset + 1 >= buffer.size()) return false;
        payloadLen = (static_cast<uint64_t>(buffer[offset]) << 8) | buffer[offset + 1];
        offset += 2;
    } else {
        if (offset + 7 >= buffer.size()) return false;
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8) | buffer[offset + i];
        }
        offset += 8;
    }
    return masked;
}

bool ParseWebSocketFrame(const std::vector<uint8_t>& buffer, WebSocketFrame& out, size_t maxPayload, std::string* error)
{
    if (buffer.size() < 2) {
        if (error) *error = "frame too small";
        return false;
    }

    size_t offset = 0;
    uint8_t first = buffer[offset++];
    out.fin = (first & 0x80) != 0;
    out.opcode = first & 0x0F;

    uint64_t payloadLen = 0;
    bool masked = parse_length(buffer, offset, payloadLen);
    out.masked = masked;

    if (masked) {
        if (error) *error = "masked frame not allowed for server";
        return false;
    }
    if (payloadLen > maxPayload) {
        if (error) *error = "payload exceeds limit";
        return false;
    }
    if (offset + payloadLen > buffer.size()) {
        if (error) *error = "truncated frame";
        return false;
    }

    out.payload.assign(buffer.begin() + offset, buffer.begin() + offset + payloadLen);
    return true;
}

bool IsFrameTooLarge(const std::vector<uint8_t>& buffer, size_t maxPayload)
{
    WebSocketFrame frame{};
    std::string err;
    return !ParseWebSocketFrame(buffer, frame, maxPayload, &err) && err == "payload exceeds limit";
}

bool IsFrameMasked(const std::vector<uint8_t>& buffer)
{
    WebSocketFrame frame{};
    std::string err;
    return !ParseWebSocketFrame(buffer, frame, 1 << 20, &err) && err == "masked frame not allowed for server";
}

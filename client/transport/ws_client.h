#pragma once

#include "../WSSClient.h"
#include <string>
#include <vector>

struct WssEndpoint {
    std::string host;
    std::wstring path;
};

WssEndpoint ParseWssEndpoint(const char* serverIP);

// Thin adapter that exposes a TCP-like interface over WebSockets so existing
// modules can reuse the serializer/AES pipeline without caring about WebSocket
// framing.
class WebSocketTransportAdapter : public WSSClient
{
public:
    WebSocketTransportAdapter(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
                              const std::string& publicIP, const std::wstring& path);

    int SendFramed(const std::vector<uint8_t>& payload);

    // Reads a single frame into the provided vector. Returns number of payload bytes or 0 on failure.
    int RecvFramed(std::vector<uint8_t>& out);
};


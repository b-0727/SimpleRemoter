#pragma once

#include "../WSSClient.h"
#include <string>
#include <vector>

struct WssEndpoint {
    std::string host;
    std::wstring path;
};

WssEndpoint ParseWssEndpoint(const char* serverIP);

// Thin adapter that exposes explicit WebSocket frame wrapping/unwrapping for
// call-sites that still expect raw TCP buffers. The underlying socket is managed
// by WSSClient; this file simply forwards payloads through the frame helpers so
// they can be injected into the existing serializer/AES pipeline.
class WebSocketTransportAdapter : public WSSClient
{
public:
    WebSocketTransportAdapter(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
                              const std::string& publicIP, const std::wstring& path);

    int SendFramed(const std::vector<uint8_t>& payload);

    // Reads a single frame into the provided vector. Returns number of payload bytes or 0 on failure.
    int RecvFramed(std::vector<uint8_t>& out);
};


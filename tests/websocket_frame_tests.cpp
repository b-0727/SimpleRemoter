#include "../common/websocket_frame.h"
#include <cassert>
#include <iostream>

int main()
{
    // basic round-trip
    std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    auto frame = BuildWebSocketFrame(payload, false, 0x2);
    WebSocketFrame decoded{};
    bool ok = ParseWebSocketFrame(frame, decoded);
    assert(ok);
    assert(!decoded.masked);
    assert(decoded.opcode == 0x2);
    assert(decoded.payload == payload);

    // masked frame rejected for server side parsing
    auto masked = BuildWebSocketFrame(payload, true, 0x2);
    assert(IsFrameMasked(masked));

    // oversized payload rejection
    std::vector<uint8_t> big(1024 * 1024 + 1, 0x41);
    auto bigFrame = BuildWebSocketFrame(big, false, 0x2);
    assert(IsFrameTooLarge(bigFrame, 1024 * 1024));

    // truncated frame rejection
    if (!bigFrame.empty()) bigFrame.pop_back();
    WebSocketFrame truncated{};
    std::string err;
    bool parsed = ParseWebSocketFrame(bigFrame, truncated, 1024 * 1024, &err);
    assert(!parsed && err == "truncated frame");

    std::cout << "websocket_frame_tests passed" << std::endl;
    return 0;
}

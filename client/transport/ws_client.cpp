#include "../WSSClient.h"
#include "../../common/websocket_frame.h"
#include <vector>

// Thin adapter that exposes explicit WebSocket frame wrapping/unwrapping for
// call-sites that still expect raw TCP buffers. The underlying socket is managed
// by WSSClient; this file simply forwards payloads through the frame helpers so
// they can be injected into the existing serializer/AES pipeline.
class WebSocketTransportAdapter : public WSSClient
{
public:
    WebSocketTransportAdapter(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
                              const std::string& publicIP)
        : WSSClient(bExit, exit_while_disconnect, mask, encoder, publicIP) {}

    int SendFramed(const std::vector<uint8_t>& payload)
    {
        auto frame = BuildWebSocketFrame(payload, false, 0x2);
        return SendTo(reinterpret_cast<const char*>(frame.data()), static_cast<int>(frame.size()), 0);
    }

    // Reads a single frame into the provided vector. Returns number of payload bytes or 0 on failure.
    int RecvFramed(std::vector<uint8_t>& out)
    {
        char buf[MAX_RECV_BUFFER] = {};
        int n = ReceiveData(buf, sizeof(buf), 0);
        if (n <= 0) return 0;
        std::vector<uint8_t> scratch(buf, buf + n);
        WebSocketFrame frame{};
        if (!ParseWebSocketFrame(scratch, frame)) {
            return 0;
        }
        out.swap(frame.payload);
        return static_cast<int>(out.size());
    }
};

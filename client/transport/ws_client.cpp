#include "ws_client.h"
#include "../../common/websocket_frame.h"
#include <vector>

WssEndpoint ParseWssEndpoint(const char* serverIP)
{
    WssEndpoint endpoint{};
    if (!serverIP) return endpoint;

    std::string target = serverIP;
    std::string path = "/";
    auto slash = target.find('/');
    if (slash != std::string::npos) {
        path = target.substr(slash);
        target = target.substr(0, slash);
    }

    endpoint.host = target;
    if (path.empty()) path = "/";
    endpoint.path.assign(path.begin(), path.end());
    return endpoint;
}

WebSocketTransportAdapter::WebSocketTransportAdapter(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
                                                     const std::string& publicIP, const std::wstring& path)
    : WSSClient(bExit, exit_while_disconnect, mask, encoder, publicIP, path)
{
}

int WebSocketTransportAdapter::SendFramed(const std::vector<uint8_t>& payload)
{
    auto frame = BuildWebSocketFrame(payload, false, 0x2);
    return SendTo(reinterpret_cast<const char*>(frame.data()), static_cast<int>(frame.size()), 0);
}

// Reads a single frame into the provided vector. Returns number of payload bytes or 0 on failure.
int WebSocketTransportAdapter::RecvFramed(std::vector<uint8_t>& out)
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


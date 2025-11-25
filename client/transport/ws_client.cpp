#include "ws_client.h"
#include "../../common/aes_gcm.h"
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
    std::vector<uint8_t> encrypted;
    if (!AesGcmEncrypt(CryptoSession(), AesGcmDirection::kClientToServer, payload, encrypted)) return 0;
    return SendTo(reinterpret_cast<const char*>(encrypted.data()), static_cast<int>(encrypted.size()), 0);
}

// Reads a single frame into the provided vector. Returns number of payload bytes or 0 on failure.
int WebSocketTransportAdapter::RecvFramed(std::vector<uint8_t>& out)
{
    char buf[MAX_RECV_BUFFER] = {};
    int n = ReceiveData(buf, sizeof(buf), 0);
    if (n <= 0) return 0;
    std::vector<uint8_t> cipher(buf, buf + n);
    if (!AesGcmDecrypt(CryptoSession(), AesGcmDirection::kServerToClient, cipher, out)) return 0;
    return static_cast<int>(out.size());
}


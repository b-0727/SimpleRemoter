#pragma once

#include "IOCPClient.h"
#include "common/aes_gcm.h"
#ifdef _WIN32
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <curl/curl.h>
#include <memory>
#include <string>
#include <vector>
#include <unordered_set>
#endif

// A transport that wraps IOCPClient over a WebSocket (WSS) connection.
// It upgrades via WinHTTP and then reuses the base event loop while
// translating send/receive calls into WebSocket frames.
class WSSClient : public IOCPClient {
public:
#ifdef _WIN32
    WSSClient(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
              const std::string& pubIP = "", const std::wstring& path = L"/")
        : IOCPClient(bExit, exit_while_disconnect, mask, encoder, pubIP),
          m_hSession(NULL), m_hConnection(NULL), m_hRequest(NULL), m_hWebSocket(NULL),
          m_path(path) {}
#else
    WSSClient(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
              const std::string& pubIP = "", const std::wstring& path = L"/")
        : IOCPClient(bExit, exit_while_disconnect, mask, encoder, pubIP),
          m_path(path.begin(), path.end()) {}
#endif
    ~WSSClient();

    BOOL ConnectServer(const char* szServerIP, unsigned short uPort) override;

    void SetEncryptionKey(const std::vector<uint8_t>& key)
    {
        m_masterKey = key;
    }

    void SetAuthToken(const std::string& token) { m_authToken = token; }
    void SetOrigin(const std::string& origin) { m_origin = origin; }

protected:
    bool EncryptPayload(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher, AeadDirection dir);
    bool DecryptPayload(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain, AeadDirection dir);

    int ReceiveData(char* buffer, int bufSize, int flags) override;
    int SendTo(const char* buf, int len, int flags) override;
    VOID Disconnect() override;

private:
#ifdef _WIN32
    HINTERNET m_hSession;
    HINTERNET m_hConnection;
    HINTERNET m_hRequest;
    HINTERNET m_hWebSocket;
    std::wstring m_path;
    std::string m_authToken;
    std::string m_origin;
    std::vector<uint8_t> m_masterKey;
    DerivedSessionKey m_sessionKey;
    uint64_t m_sendSeq = 0;
    uint64_t m_recvSeq = 0;
    std::unordered_set<uint64_t> m_seenNonces;
    std::unordered_set<uint64_t> m_seenPeerNonces;
    uint64_t m_highSeen = 0;
    uint64_t m_highPeer = 0;

    void CloseHandles();
    static std::wstring AnsiToWide(const char* src);
#else
    std::unique_ptr<boost::asio::io_context> m_ioContext;
    std::unique_ptr<boost::asio::ssl::context> m_sslContext;
    std::unique_ptr<boost::beast::websocket::stream<
        boost::beast::ssl_stream<boost::beast::tcp_stream>>> m_websocket;
    std::string m_path;
    std::string m_authToken;
    std::string m_origin;
    std::vector<uint8_t> m_masterKey;
    DerivedSessionKey m_sessionKey;
    uint64_t m_sendSeq = 0;
    uint64_t m_recvSeq = 0;
    std::unordered_set<uint64_t> m_seenNonces;
    std::unordered_set<uint64_t> m_seenPeerNonces;
    uint64_t m_highSeen = 0;
    uint64_t m_highPeer = 0;

    std::string NormalizePath(const std::string& path);
#endif
};


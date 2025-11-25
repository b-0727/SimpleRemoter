#ifdef _WIN32
#include "stdafx.h"
#endif
#include "WSSClient.h"
#ifndef _WIN32
#include <cstdio>
#include <stdexcept>
#include <iomanip>
#endif
#include <openssl/rand.h>
#include <sstream>

namespace {
std::string BytesToHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}
}

bool WSSClient::EncryptPayload(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher, AeadDirection dir)
{
    if (m_sessionKey.key.size() != 32) return false;
    return AesGcmEncrypt(m_sessionKey.key, plain, cipher, dir, &m_sendSeq, &m_sessionKey.salt,
                        &m_seenNonces, &m_highSeen);
}

bool WSSClient::DecryptPayload(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain, AeadDirection dir)
{
    if (m_sessionKey.key.size() != 32) return false;
    return AesGcmDecrypt(m_sessionKey.key, cipher, plain, dir, &m_sessionKey.salt,
                         &m_seenPeerNonces, &m_highPeer);
}

#ifdef _WIN32
#include <string>
#include <vector>

std::wstring WSSClient::AnsiToWide(const char* src)
{
    if (!src) return L"";
    int len = MultiByteToWideChar(CP_ACP, 0, src, -1, nullptr, 0);
    std::wstring result(len, 0);
    MultiByteToWideChar(CP_ACP, 0, src, -1, &result[0], len);
    // Trim the null terminator for convenience
    if (!result.empty() && result.back() == L'\0') result.pop_back();
    return result;
}

static std::string WideToAnsi(const wchar_t* src)
{
    if (!src) return "";
    int len = WideCharToMultiByte(CP_ACP, 0, src, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len, 0);
    WideCharToMultiByte(CP_ACP, 0, src, -1, &result[0], len, nullptr, nullptr);
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

void WSSClient::CloseHandles()
{
    if (m_hWebSocket) {
        WinHttpWebSocketClose(m_hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        WinHttpCloseHandle(m_hWebSocket);
        m_hWebSocket = NULL;
    }
    if (m_hRequest) {
        WinHttpCloseHandle(m_hRequest);
        m_hRequest = NULL;
    }
    if (m_hConnection) {
        WinHttpCloseHandle(m_hConnection);
        m_hConnection = NULL;
    }
    if (m_hSession) {
        WinHttpCloseHandle(m_hSession);
        m_hSession = NULL;
    }
}

WSSClient::~WSSClient()
{
    CloseHandles();
}

BOOL WSSClient::ConnectServer(const char* szServerIP, unsigned short uPort)
{
    // Fall back to configured domain if not provided. WSS requires the original hostname
    // for SNI, so avoid resolving it to an IP when possible.
    std::string host = szServerIP && szServerIP[0] ? szServerIP : m_Domain.SelectHost(false);
    if (host.empty()) host = m_Domain.SelectIP();
    if (host.empty()) return FALSE;
    if (m_masterKey.size() != 32) {
        Mprintf("[WSS] AES-256-GCM master key must be 32 bytes; refusing to start session.\n");
        return FALSE;
    }

    CloseHandles();
    Mprintf("[WSS] Connecting to %s:%hu over WinHTTP...\n", host.c_str(), uPort ? uPort : m_nHostPort);

    std::wstring wideHost = AnsiToWide(host.c_str());
    m_hSession = WinHttpOpen(L"SimpleRemoter-WSS/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!m_hSession) return FALSE;

    INTERNET_PORT port = uPort ? uPort : m_nHostPort;
    m_hConnection = WinHttpConnect(m_hSession, wideHost.c_str(), port, 0);
    if (!m_hConnection) {
        CloseHandles();
        return FALSE;
    }

    m_hRequest = WinHttpOpenRequest(m_hConnection, L"GET", m_path.c_str(),
                                    NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    WINHTTP_FLAG_SECURE);
    if (!m_hRequest) {
        CloseHandles();
        return FALSE;
    }

    if (!WinHttpSetOption(m_hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        CloseHandles();
        return FALSE;
    }

    // Allow upstream header injection such as X-Forwarded-For.
    std::wstring headers;
    auto headerMap = GetClientIPHeader();
    if (!headerMap.empty()) {
        for (auto& kv : headerMap) {
            std::wstring k = AnsiToWide(kv.first.c_str());
            std::wstring v = AnsiToWide(kv.second.c_str());
            headers.append(k).append(L": ").append(v).append(L"\r\n");
        }
    }
    std::array<uint8_t, 16> clientNonce{};
    RAND_bytes(clientNonce.data(), clientNonce.size());
    std::vector<uint8_t> clientNonceVec(clientNonce.begin(), clientNonce.end());
    auto clientNonceHex = BytesToHex(clientNonceVec);
    headers.append(L"X-SR-Client-Nonce: ").append(AnsiToWide(clientNonceHex.c_str())).append(L"\r\n");
    if (!m_authToken.empty()) {
        headers.append(L"Sec-WebSocket-Protocol: ").append(AnsiToWide(m_authToken.c_str())).append(L"\r\n");
    }
    if (!m_origin.empty()) {
        headers.append(L"Origin: ").append(AnsiToWide(m_origin.c_str())).append(L"\r\n");
    }

    std::string pathAnsi(m_path.begin(), m_path.end());
    Mprintf("[WSS] Sending HTTP upgrade request to %s%s...\n", host.c_str(), pathAnsi.c_str());
    if (!WinHttpSendRequest(m_hRequest,
                            headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                            headers.empty() ? 0 : (DWORD)-1,
                            WINHTTP_NO_REQUEST_DATA, 0,
                            WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0)) {
        CloseHandles();
        return FALSE;
    }

    if (!WinHttpReceiveResponse(m_hRequest, NULL)) {
        CloseHandles();
        return FALSE;
    }

    if (!m_authToken.empty()) {
        DWORD protoLen = 0;
        WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_CUSTOM, L"Sec-WebSocket-Protocol", NULL, &protoLen, WINHTTP_NO_HEADER_INDEX);
        std::wstring proto(protoLen / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_CUSTOM, L"Sec-WebSocket-Protocol", proto.data(), &protoLen, WINHTTP_NO_HEADER_INDEX)) {
            CloseHandles();
            return FALSE;
        }
        proto.resize((protoLen / sizeof(wchar_t)) - 1);
        if (proto != AnsiToWide(m_authToken.c_str())) {
            Mprintf("[WSS] Gateway rejected Sec-WebSocket-Protocol token.\n");
            CloseHandles();
            return FALSE;
        }
    }

    DWORD nonceLen = 0;
    WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_CUSTOM, L"X-SR-Server-Nonce", NULL, &nonceLen, WINHTTP_NO_HEADER_INDEX);
    std::wstring serverNonceWide(nonceLen / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_CUSTOM, L"X-SR-Server-Nonce", serverNonceWide.data(), &nonceLen, WINHTTP_NO_HEADER_INDEX)) {
        CloseHandles();
        return FALSE;
    }
    serverNonceWide.resize((nonceLen / sizeof(wchar_t)) - 1);
    auto serverNonce = HexToBytes(WideToAnsi(serverNonceWide.c_str()));
    if (serverNonce.size() < 16) {
        CloseHandles();
        return FALSE;
    }
    m_sessionKey = DeriveSessionKey(m_masterKey, clientNonceVec, serverNonce);
    if (m_sessionKey.key.size() != 32) {
        CloseHandles();
        return FALSE;
    }
    m_sendSeq = m_recvSeq = 0;
    m_seenNonces.clear();
    m_seenPeerNonces.clear();
    m_highSeen = m_highPeer = 0;

    m_hWebSocket = WinHttpWebSocketCompleteUpgrade(m_hRequest, 0);
    if (!m_hWebSocket) {
        CloseHandles();
        return FALSE;
    }

    Mprintf("[WSS] Upgrade complete; WebSocket open.\n");
    m_bConnected = TRUE;
    m_sCurIP = host;
    return TRUE;
}

int WSSClient::ReceiveData(char* buffer, int bufSize, int /*flags*/)
{
    if (!m_hWebSocket || bufSize <= 0) return 0;

    WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    DWORD dwBytesRead = 0;
    std::vector<uint8_t> cipher(bufSize);
    HRESULT hr = WinHttpWebSocketReceive(m_hWebSocket, cipher.data(), bufSize, &dwBytesRead, &type);
    if (FAILED(hr) || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
        m_bConnected = FALSE;
        return 0;
    }
    cipher.resize(dwBytesRead);
    std::vector<uint8_t> plain;
    if (!DecryptPayload(cipher, plain, AeadDirection::ServerToClient)) return 0;
    if (plain.size() > static_cast<size_t>(bufSize)) return 0;
    memcpy(buffer, plain.data(), plain.size());
    return static_cast<int>(plain.size());
}

int WSSClient::SendTo(const char* buf, int len, int /*flags*/)
{
    if (!m_hWebSocket || len <= 0) return SOCKET_ERROR;
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> plain(buf, buf + len);
    if (!EncryptPayload(plain, cipher, AeadDirection::ClientToServer)) return SOCKET_ERROR;
    HRESULT hr = WinHttpWebSocketSend(m_hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                      cipher.data(), static_cast<DWORD>(cipher.size()));
    if (FAILED(hr)) return SOCKET_ERROR;
    return len;
}

VOID WSSClient::Disconnect()
{
    CloseHandles();
    m_bConnected = FALSE;
}

#else
// Cross-platform WebSocket implementation using Boost.Asio/Beast with libcurl
// URL normalization to mirror the WinHTTP code-path on Windows.
WSSClient::~WSSClient()
{
    Disconnect();
}

std::string WSSClient::NormalizePath(const std::string& path)
{
    if (path.empty() || path[0] == '/') return path.empty() ? std::string("/") : path;
    return std::string("/") + path;
}

BOOL WSSClient::ConnectServer(const char* szServerIP, unsigned short uPort)
{
    std::string host = szServerIP && szServerIP[0] ? szServerIP : m_Domain.SelectHost(false);
    if (host.empty()) host = m_Domain.SelectIP();
    if (host.empty()) return FALSE;

    unsigned short port = uPort ? uPort : m_nHostPort;
    std::string path = NormalizePath(m_path);

    // Normalize host/path with libcurl to keep behavior aligned with WinHTTP upgrades.
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURLU* url = curl_url();
    if (url) {
        curl_url_set(url, CURLUPART_SCHEME, "wss", 0);
        curl_url_set(url, CURLUPART_HOST, host.c_str(), 0);
        if (port) {
            char portBuf[8] = {};
            snprintf(portBuf, sizeof(portBuf), "%hu", port);
            curl_url_set(url, CURLUPART_PORT, portBuf, 0);
        }
        curl_url_set(url, CURLUPART_PATH, path.c_str(), CURLU_URLENCODE);

        char* normalizedHost = nullptr;
        if (curl_url_get(url, CURLUPART_HOST, &normalizedHost, 0) == CURLUE_OK && normalizedHost) {
            host.assign(normalizedHost);
            curl_free(normalizedHost);
        }
        char* normalizedPath = nullptr;
        if (curl_url_get(url, CURLUPART_PATH, &normalizedPath, 0) == CURLUE_OK && normalizedPath) {
            path.assign(normalizedPath);
            curl_free(normalizedPath);
        }
        curl_url_cleanup(url);
    }

    try {
        if (m_masterKey.size() != 32) {
            Mprintf("[WSS] AES-256-GCM master key must be 32 bytes; refusing to start session.\n");
            return FALSE;
        }
        Mprintf("[WSS] Resolving %s:%hu over TLS...\n", host.c_str(), port);
        m_ioContext = std::make_unique<boost::asio::io_context>();
        m_sslContext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client);
        m_sslContext->set_verify_mode(boost::asio::ssl::verify_peer);
        m_sslContext->set_verify_callback(boost::asio::ssl::rfc2818_verification(host));
        m_sslContext->set_default_verify_paths();

        std::array<uint8_t, 16> clientNonce{};
        RAND_bytes(clientNonce.data(), clientNonce.size());
        std::vector<uint8_t> clientNonceVec(clientNonce.begin(), clientNonce.end());
        auto clientNonceHex = BytesToHex(clientNonceVec);

        m_websocket = std::make_unique<boost::beast::websocket::stream<
            boost::beast::ssl_stream<boost::beast::tcp_stream>>>(*m_ioContext, *m_sslContext);
        auto& ws = *m_websocket;
        auto& sslStream = ws.next_layer();
        auto& tcpStream = boost::beast::get_lowest_layer(ws);

        boost::asio::ip::tcp::resolver resolver(*m_ioContext);
        auto results = resolver.resolve(host, port ? std::to_string(port) : std::string("443"));
        tcpStream.connect(results);
        Mprintf("[WSS] TCP connected, performing TLS handshake...\n");

        // SNI
        if (!SSL_set_tlsext_host_name(sslStream.native_handle(), host.c_str())) {
            throw std::runtime_error("Failed to set SNI host name");
        }

        sslStream.handshake(boost::asio::ssl::stream_base::client);
        Mprintf("[WSS] TLS handshake complete, upgrading to WebSocket at %s...\n", path.c_str());

        auto extraHeaders = GetClientIPHeader();
        ws.set_option(boost::beast::websocket::stream_base::decorator([
            extraHeaders, clientNonceHex, this
        ](boost::beast::websocket::request_type& req) {
            req.set(boost::beast::http::field::user_agent, "SimpleRemoter-WSS/1.0");
            for (const auto& kv : extraHeaders) {
                req.set(kv.first, kv.second);
            }
            if (!this->m_authToken.empty()) {
                req.set(boost::beast::http::field::sec_websocket_protocol, this->m_authToken);
            }
            if (!this->m_origin.empty()) {
                req.set(boost::beast::http::field::origin, this->m_origin);
            }
            req.set("X-SR-Client-Nonce", clientNonceHex);
        }));

        ws.binary(true);
        ws.handshake(host + (port ? std::string(":") + std::to_string(port) : std::string("")), path);

        auto response = ws.response();
        auto protoIt = response.find(boost::beast::http::field::sec_websocket_protocol);
        if (!m_authToken.empty() && (protoIt == response.end() || protoIt->value() != m_authToken)) {
            throw std::runtime_error("WSS auth token rejected by gateway");
        }
        auto serverNonceIt = response.find("X-SR-Server-Nonce");
        if (serverNonceIt == response.end()) {
            throw std::runtime_error("Missing server nonce during handshake");
        }
        auto serverNonce = HexToBytes(serverNonceIt->value().to_string());
        if (serverNonce.size() < 16) {
            throw std::runtime_error("Invalid server nonce length");
        }
        m_sessionKey = DeriveSessionKey(m_masterKey, clientNonceVec, serverNonce);
        if (m_sessionKey.key.size() != 32) {
            throw std::runtime_error("Failed to derive session key");
        }
        m_sendSeq = m_recvSeq = 0;
        m_seenNonces.clear();
        m_seenPeerNonces.clear();
        m_highSeen = m_highPeer = 0;

        Mprintf("[WSS] WebSocket upgrade complete.\n");
        m_bConnected = TRUE;
        m_sCurIP = host;
        return TRUE;
    } catch (const std::exception& ex) {
        Mprintf("WSS connect failed: %s\n", ex.what());
    }

    Disconnect();
    return FALSE;
}

int WSSClient::ReceiveData(char* buffer, int bufSize, int /*flags*/)
{
    if (!m_websocket || !buffer || bufSize <= 0) return 0;
    try {
        boost::beast::flat_buffer fb;
        m_websocket->read(fb);
        auto data = fb.data();
        std::vector<uint8_t> cipher(boost::asio::buffers_begin(data), boost::asio::buffers_end(data));
        std::vector<uint8_t> plain;
        if (!DecryptPayload(cipher, plain, AeadDirection::ServerToClient)) return 0;
        if (static_cast<int>(plain.size()) > bufSize) {
            Mprintf("Receive buffer too small for decrypted payload: %zu bytes\n", plain.size());
            return 0;
        }
        memcpy(buffer, plain.data(), plain.size());
        return static_cast<int>(plain.size());
    } catch (const std::exception& ex) {
        Mprintf("WSS receive failed: %s\n", ex.what());
    }

    m_bConnected = FALSE;
    return 0;
}

int WSSClient::SendTo(const char* buf, int len, int /*flags*/)
{
    if (!m_websocket || !buf || len <= 0) return SOCKET_ERROR;
    try {
        std::vector<uint8_t> cipher;
        std::vector<uint8_t> plain(buf, buf + len);
        if (!EncryptPayload(plain, cipher, AeadDirection::ClientToServer)) return SOCKET_ERROR;
        m_websocket->binary(true);
        m_websocket->write(boost::asio::buffer(cipher));
        return len;
    } catch (const std::exception& ex) {
        Mprintf("WSS send failed: %s\n", ex.what());
    }
    m_bConnected = FALSE;
    return SOCKET_ERROR;
}

VOID WSSClient::Disconnect()
{
    if (m_websocket) {
        try {
            m_websocket->close(boost::beast::websocket::close_code::normal);
        } catch (...) {
        }
        m_websocket.reset();
    }
    m_sslContext.reset();
    m_ioContext.reset();
    m_bConnected = FALSE;
}

#endif // _WIN32


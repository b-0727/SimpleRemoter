#ifdef _WIN32
#include "stdafx.h"
#endif
#include "WSSClient.h"
#ifndef _WIN32
#include <cstdio>
#include <stdexcept>
#endif

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
    HRESULT hr = WinHttpWebSocketReceive(m_hWebSocket, buffer, bufSize, &dwBytesRead, &type);
    if (FAILED(hr) || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
        m_bConnected = FALSE;
        return 0;
    }
    return static_cast<int>(dwBytesRead);
}

int WSSClient::SendTo(const char* buf, int len, int /*flags*/)
{
    if (!m_hWebSocket || len <= 0) return SOCKET_ERROR;
    HRESULT hr = WinHttpWebSocketSend(m_hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                      (void*)buf, len);
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
        Mprintf("[WSS] Resolving %s:%hu over TLS...\n", host.c_str(), port);
        m_ioContext = std::make_unique<boost::asio::io_context>();
        m_sslContext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client);
        m_sslContext->set_verify_mode(boost::asio::ssl::verify_peer);
        m_sslContext->set_verify_callback(boost::asio::ssl::rfc2818_verification(host));
        m_sslContext->set_default_verify_paths();

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
            extraHeaders
        ](boost::beast::websocket::request_type& req) {
            req.set(boost::beast::http::field::user_agent, "SimpleRemoter-WSS/1.0");
            for (const auto& kv : extraHeaders) {
                req.set(kv.first, kv.second);
            }
        }));

        ws.binary(true);
        ws.handshake(host + (port ? std::string(":") + std::to_string(port) : std::string("")), path);

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
        auto readable = fb.size();
        if (readable == 0) return 0;
        if (static_cast<int>(readable) > bufSize) {
            Mprintf("Receive buffer too small for WebSocket frame: %zu bytes\n", readable);
            return 0;
        }
        auto data = fb.data();
        boost::asio::buffer_copy(boost::asio::buffer(buffer, bufSize), data);
        return static_cast<int>(readable);
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
        m_websocket->binary(true);
        m_websocket->write(boost::asio::buffer(buf, len));
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


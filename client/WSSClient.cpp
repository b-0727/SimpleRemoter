#include "stdafx.h"
#include "WSSClient.h"

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
    // Fall back to configured domain if not provided.
    std::string host = szServerIP && szServerIP[0] ? szServerIP : m_Domain.GetCurrent();
    if (host.empty()) return FALSE;

    CloseHandles();

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
// Non-Windows builds keep the interface compilable but act as no-op.
WSSClient::~WSSClient() {}

BOOL WSSClient::ConnectServer(const char* /*szServerIP*/, unsigned short /*uPort*/)
{
    return FALSE;
}

int WSSClient::ReceiveData(char* /*buffer*/, int /*bufSize*/, int /*flags*/)
{
    return 0;
}

int WSSClient::SendTo(const char* /*buf*/, int /*len*/, int /*flags*/)
{
    return SOCKET_ERROR;
}

VOID WSSClient::Disconnect()
{
    m_bConnected = FALSE;
}

#endif // _WIN32


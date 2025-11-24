#pragma once

#include "IOCPClient.h"
#ifdef _WIN32
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

// A transport that wraps IOCPClient over a WebSocket (WSS) connection.
// It upgrades via WinHTTP and then reuses the base event loop while
// translating send/receive calls into WebSocket frames.
class WSSClient : public IOCPClient {
public:
    WSSClient(const State& bExit, bool exit_while_disconnect, int mask, int encoder,
              const std::string& pubIP = "", const std::wstring& path = L"/")
        : IOCPClient(bExit, exit_while_disconnect, mask, encoder, pubIP),
          m_hSession(NULL), m_hConnection(NULL), m_hRequest(NULL), m_hWebSocket(NULL),
          m_path(path) {}
    ~WSSClient();

    BOOL ConnectServer(const char* szServerIP, unsigned short uPort) override;

protected:
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

    void CloseHandles();
    static std::wstring AnsiToWide(const char* src);
#endif
};


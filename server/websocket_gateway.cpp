#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "common/encrypt.h"
#include "common/header.h"
#include "common/mask.h"
#include "common/websocket_frame.h"

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include "server/2015Remote/Server.h"
#pragma comment(lib, "Ws2_32.lib")
#else
#include <boost/asio.hpp>
#include <openssl/sha.h>
#endif

namespace {
#ifndef _WIN32
std::string base64_encode(const unsigned char* data, size_t len)
{
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    std::string ret;
    ret.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (size_t j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (size_t j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}
#endif

struct GatewayConfig {
    std::string bindAddress = "0.0.0.0";
    uint16_t port = 24443;
    size_t maxPayload = 1 << 20;
};

class WebSocketFramePump {
public:
    explicit WebSocketFramePump(size_t maxPayload) : maxPayload_(maxPayload) {}

    std::vector<uint8_t> Wrap(const std::vector<uint8_t>& payload, uint8_t opcode = 0x2)
    {
        return BuildWebSocketFrame(payload, false, opcode);
    }

    bool Unwrap(const std::vector<uint8_t>& buffer, WebSocketFrame& frame, std::string& err)
    {
        return ParseWebSocketFrame(buffer, frame, maxPayload_, &err);
    }

private:
    size_t maxPayload_;
};

class PayloadPipeline {
public:
    virtual ~PayloadPipeline() = default;
    virtual void OnInbound(const std::vector<uint8_t>& payload,
                           const std::function<void(const std::vector<uint8_t>&)>& forward) = 0;
};

#ifdef _WIN32
class HeaderParserPipeline : public PayloadPipeline {
public:
    void OnInbound(const std::vector<uint8_t>& payload,
                   const std::function<void(const std::vector<uint8_t>&)>& forward) override
    {
        in_.WriteBuffer(const_cast<PBYTE>(payload.data()), static_cast<ULONG>(payload.size()));
        while (true) {
            std::string peer;
            PR pr = parser_.Parse(in_, compressMethod_, peer);
            if (pr.IsFailed() || pr.IsNeedMore()) {
                break;
            }
            ULONG totalLen = 0;
            in_.CopyBuffer(&totalLen, sizeof(ULONG), pr.Result);
            if (totalLen == 0 || in_.GetBufferLength() < totalLen) {
                break;
            }
            ULONG compressedLen = 0;
            ULONG originalLen = 0;
            PBYTE compressed = parser_.ReadBuffer(compressedLen, originalLen);
            if (!compressed) {
                break;
            }
            std::vector<uint8_t> body(compressed, compressed + compressedLen);
            delete[] compressed;
            forward(body);
        }
    }

private:
    HeaderParser parser_;
    CBuffer in_;
    int compressMethod_ = COMPRESS_ZSTD;
};
#else
class PassthroughPipeline : public PayloadPipeline {
public:
    void OnInbound(const std::vector<uint8_t>& payload,
                   const std::function<void(const std::vector<uint8_t>&)>& forward) override
    {
        forward(payload);
    }
};
#endif

#ifndef _WIN32
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    WebSocketSession(boost::asio::ip::tcp::socket socket, GatewayConfig cfg)
        : socket_(std::move(socket)), config_(cfg), framer_(cfg.maxPayload),
          pipeline_(std::make_unique<PassthroughPipeline>())
    {
    }

    void Start()
    {
        std::thread([self = shared_from_this()]() { self->Run(); }).detach();
    }

private:
    boost::asio::ip::tcp::socket socket_;
    GatewayConfig config_;
    WebSocketFramePump framer_;
    std::unique_ptr<PayloadPipeline> pipeline_;

    void Run()
    {
        try {
            if (!DoHandshake()) {
                return;
            }
            ReadLoop();
        } catch (const std::exception& ex) {
            std::cerr << "websocket session error: " << ex.what() << std::endl;
        }
    }

    bool DoHandshake()
    {
        boost::asio::streambuf requestBuf;
        boost::asio::read_until(socket_, requestBuf, "\r\n\r\n");
        std::istream requestStream(&requestBuf);
        std::string request((std::istreambuf_iterator<char>(requestStream)), {});
        if (request.find("Upgrade: websocket") == std::string::npos) {
            return false;
        }
        auto keyPos = request.find("Sec-WebSocket-Key: ");
        if (keyPos == std::string::npos) return false;
        keyPos += strlen("Sec-WebSocket-Key: ");
        auto end = request.find("\r\n", keyPos);
        std::string key = request.substr(keyPos, end - keyPos);
        key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());

        const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string acceptSrc = key + magic;
        unsigned char sha1Hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(acceptSrc.data()), acceptSrc.size(), sha1Hash);
        std::string accept = base64_encode(sha1Hash, SHA_DIGEST_LENGTH);

        std::ostringstream resp;
        resp << "HTTP/1.1 101 Switching Protocols\r\n"
             << "Upgrade: websocket\r\n"
             << "Connection: Upgrade\r\n"
             << "Sec-WebSocket-Accept: " << accept << "\r\n\r\n";
        auto responseStr = resp.str();
        boost::asio::write(socket_, boost::asio::buffer(responseStr));
        return true;
    }

    void ReadLoop()
    {
        while (socket_.is_open()) {
            std::vector<uint8_t> header(2);
            boost::asio::read(socket_, boost::asio::buffer(header));
            uint8_t opcode = header[0] & 0x0F;
            bool fin = (header[0] & 0x80) != 0;
            uint8_t lenByte = header[1];
            bool masked = (lenByte & 0x80) != 0;
            uint64_t payloadLen = (lenByte & 0x7F);
            if (payloadLen == 126) {
                std::array<uint8_t, 2> ext;
                boost::asio::read(socket_, boost::asio::buffer(ext));
                payloadLen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
            } else if (payloadLen == 127) {
                std::array<uint8_t, 8> ext;
                boost::asio::read(socket_, boost::asio::buffer(ext));
                payloadLen = 0;
                for (auto b : ext) {
                    payloadLen = (payloadLen << 8) | b;
                }
            }
            std::vector<uint8_t> maskingKey(masked ? 4 : 0);
            if (masked) {
                boost::asio::read(socket_, boost::asio::buffer(maskingKey));
            }
            std::vector<uint8_t> payload(payloadLen);
            if (payloadLen) {
                boost::asio::read(socket_, boost::asio::buffer(payload));
            }
            if (masked) {
                for (size_t i = 0; i < payload.size(); ++i) {
                    payload[i] ^= maskingKey[i % 4];
                }
            }
            std::vector<uint8_t> frameBuf;
            frameBuf.reserve(2 + (masked ? 4 : 0) + payload.size());
            uint8_t first = static_cast<uint8_t>(fin ? 0x80 : 0x00) | (opcode & 0x0F);
            frameBuf.push_back(first);
            if (payloadLen < 126) {
                frameBuf.push_back(static_cast<uint8_t>(payloadLen));
            } else if (payloadLen <= 0xFFFF) {
                frameBuf.push_back(126);
                frameBuf.push_back(static_cast<uint8_t>((payloadLen >> 8) & 0xFF));
                frameBuf.push_back(static_cast<uint8_t>(payloadLen & 0xFF));
            } else {
                frameBuf.push_back(127);
                for (int i = 7; i >= 0; --i) {
                    frameBuf.push_back(static_cast<uint8_t>((payloadLen >> (i * 8)) & 0xFF));
                }
            }
            frameBuf.insert(frameBuf.end(), payload.begin(), payload.end());
            WebSocketFrame frame{};
            std::string err;
            if (!framer_.Unwrap(frameBuf, frame, err)) {
                std::cerr << "invalid frame: " << err << std::endl;
                SendClose();
                break;
            }
            HandleFrame(frame);
        }
    }

    void HandleFrame(const WebSocketFrame& frame)
    {
        switch (frame.opcode) {
        case 0x8:
            SendClose();
            break;
        case 0x9:
            SendPong(frame.payload);
            break;
        case 0xA:
            break;
        default:
            pipeline_->OnInbound(frame.payload, [this](const std::vector<uint8_t>& msg) {
                auto wrapped = framer_.Wrap(msg, 0x2);
                boost::asio::write(socket_, boost::asio::buffer(wrapped));
            });
            break;
        }
    }

    void SendClose()
    {
        if (!socket_.is_open()) return;
        auto frame = framer_.Wrap({}, 0x8);
        boost::system::error_code ec;
        boost::asio::write(socket_, boost::asio::buffer(frame), ec);
        socket_.close();
    }

    void SendPong(const std::vector<uint8_t>& data)
    {
        auto frame = framer_.Wrap(data, 0xA);
        boost::asio::write(socket_, boost::asio::buffer(frame));
    }
};

class WebSocketGateway {
public:
    explicit WebSocketGateway(const GatewayConfig& cfg)
        : io_(), acceptor_(io_), config_(cfg)
    {
    }

    void Run()
    {
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address(config_.bindAddress), config_.port);
        acceptor_.open(ep.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(ep);
        acceptor_.listen();
        AcceptLoop();
        io_.run();
    }

private:
    boost::asio::io_context io_;
    boost::asio::ip::tcp::acceptor acceptor_;
    GatewayConfig config_;

    void AcceptLoop()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                std::make_shared<WebSocketSession>(std::move(socket), config_)->Start();
            }
            AcceptLoop();
        });
    }
};
#endif
} // namespace

int main(int argc, char* argv[])
{
    GatewayConfig cfg;
    if (argc > 1) {
        cfg.port = static_cast<uint16_t>(std::stoi(argv[1]));
    }
    if (argc > 2) {
        cfg.maxPayload = static_cast<size_t>(std::stoul(argv[2]));
    }
#ifdef _WIN32
    std::cerr << "Windows WebSocket listener placeholder for IOCP/WinHTTP integration." << std::endl;
#else
    WebSocketGateway gateway(cfg);
    gateway.Run();
#endif
    return 0;
}


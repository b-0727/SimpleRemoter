#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "common/aes_gcm.h"
#include "common/websocket_frame.h"

#include <boost/asio.hpp>
#include <openssl/sha.h>
#include <boost/asio/ssl.hpp>

namespace {
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

struct GatewayConfig {
    std::string bindAddress = "0.0.0.0";
    uint16_t port = 24443;
    size_t maxPayload = 1 << 20;
    std::string upstreamHost = "127.0.0.1";
    uint16_t upstreamPort = 6543;
    bool useTls = false;
    std::string certificateFile;
    std::string privateKeyFile;
    std::vector<uint8_t> encryptionKey;
};

GatewayConfig LoadConfigFromFile(const std::string& path, const GatewayConfig& defaults)
{
    GatewayConfig cfg = defaults;
    std::ifstream in(path);
    if (!in) return cfg;

    auto trim = [](const std::string& s) {
        auto begin = s.find_first_not_of(" \t\r\n");
        auto end = s.find_last_not_of(" \t\r\n");
        if (begin == std::string::npos) return std::string();
        return s.substr(begin, end - begin + 1);
    };

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        if (key == "bind") cfg.bindAddress = value;
        else if (key == "port") cfg.port = static_cast<uint16_t>(std::stoi(value));
        else if (key == "max_payload") cfg.maxPayload = static_cast<size_t>(std::stoul(value));
        else if (key == "upstream_host") cfg.upstreamHost = value;
        else if (key == "upstream_port") cfg.upstreamPort = static_cast<uint16_t>(std::stoi(value));
        else if (key == "encryption_key") cfg.encryptionKey = HexToBytes(value);
        else if (key == "use_tls") cfg.useTls = (value == "1" || value == "true" || value == "TRUE");
        else if (key == "certificate") cfg.certificateFile = value;
        else if (key == "private_key") cfg.privateKeyFile = value;
    }
    return cfg;
}

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

template <typename Stream>
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession<Stream>> {
public:
    WebSocketSession(Stream stream, GatewayConfig cfg, boost::asio::io_context& io)
        : stream_(std::move(stream)), config_(std::move(cfg)), framer_(config_.maxPayload),
          io_(io), upstream_(io), open_(true)
    {
    }

    void Start()
    {
        std::thread([self = this->shared_from_this()]() { self->Run(); }).detach();
    }

private:
    Stream stream_;
    GatewayConfig config_;
    WebSocketFramePump framer_;
    boost::asio::io_context& io_;
    boost::asio::ip::tcp::socket upstream_;
    std::mutex writeMutex_;
    bool open_;

    bool PerformTransportHandshake()
    {
        if constexpr (std::is_same_v<Stream, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>) {
            stream_.set_verify_mode(boost::asio::ssl::verify_none);
            stream_.handshake(boost::asio::ssl::stream_base::server);
        }
        return true;
    }

    void Run()
    {
        try {
            if (!PerformTransportHandshake()) { SendClose(); return; }
            if (!DoHandshake()) { SendClose(); return; }
            if (!ConnectUpstream()) { SendClose(); return; }
            PumpUpstream();
            ReadLoop();
        } catch (const std::exception& ex) {
            std::cerr << "websocket session error: " << ex.what() << std::endl;
            SendClose();
        }
    }

    bool DoHandshake()
    {
        boost::asio::streambuf requestBuf;
        boost::asio::read_until(stream_, requestBuf, "\r\n\r\n");
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
        boost::asio::write(stream_, boost::asio::buffer(responseStr));
        return true;
    }

    bool ConnectUpstream()
    {
        boost::system::error_code ec;
        boost::asio::ip::tcp::resolver resolver(io_);
        auto endpoints = resolver.resolve(config_.upstreamHost, std::to_string(config_.upstreamPort), ec);
        if (ec) {
            std::cerr << "resolve upstream failed: " << ec.message() << std::endl;
            return false;
        }
        boost::asio::connect(upstream_, endpoints, ec);
        if (ec) {
            std::cerr << "connect upstream failed: " << ec.message() << std::endl;
            return false;
        }
        return true;
    }

    void PumpUpstream()
    {
        auto self = this->shared_from_this();
        std::thread([self]() {
            try {
                std::vector<uint8_t> buffer(4096);
                while (self->open_) {
                    boost::system::error_code ec;
                    size_t n = self->upstream_.read_some(boost::asio::buffer(buffer), ec);
                    if (ec) break;
                    std::vector<uint8_t> payload(buffer.begin(), buffer.begin() + n);
                    std::vector<uint8_t> encrypted;
                    if (!AesGcmEncrypt(self->config_.encryptionKey, payload, encrypted)) {
                        break;
                    }
                    auto frame = self->framer_.Wrap(encrypted, 0x2);
                    self->WriteFrame(frame);
                }
            } catch (const std::exception& ex) {
                std::cerr << "upstream pump error: " << ex.what() << std::endl;
            }
            self->SendClose();
        }).detach();
    }

    void ReadLoop()
    {
        while (open_) {
            std::vector<uint8_t> header(2);
            boost::asio::read(stream_, boost::asio::buffer(header));
            uint8_t opcode = header[0] & 0x0F;
            uint8_t lenByte = header[1];
            bool masked = (lenByte & 0x80) != 0;
            uint64_t payloadLen = (lenByte & 0x7F);
            if (payloadLen == 126) {
                std::array<uint8_t, 2> ext{};
                boost::asio::read(stream_, boost::asio::buffer(ext));
                payloadLen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
            } else if (payloadLen == 127) {
                std::array<uint8_t, 8> ext{};
                boost::asio::read(stream_, boost::asio::buffer(ext));
                payloadLen = 0;
                for (auto b : ext) {
                    payloadLen = (payloadLen << 8) | b;
                }
            }
            if (payloadLen > config_.maxPayload) {
                std::cerr << "payload length " << payloadLen << " exceeds maxPayload " << config_.maxPayload
                          << std::endl;
                SendClose();
                break;
            }
            std::vector<uint8_t> maskingKey(masked ? 4 : 0);
            if (masked) {
                boost::asio::read(stream_, boost::asio::buffer(maskingKey));
            }
            std::vector<uint8_t> payload(payloadLen);
            if (payloadLen) {
                boost::asio::read(stream_, boost::asio::buffer(payload));
            }
            if (masked) {
                for (size_t i = 0; i < payload.size(); ++i) {
                    payload[i] ^= maskingKey[i % 4];
                }
            }

            std::vector<uint8_t> frameBuf;
            frameBuf.reserve(2 + (masked ? 4 : 0) + payload.size());
            uint8_t first = static_cast<uint8_t>((header[0] & 0x80) ? 0x80 : 0x00) | (opcode & 0x0F);
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
        default: {
            std::vector<uint8_t> decrypted;
            if (!AesGcmDecrypt(config_.encryptionKey, frame.payload, decrypted)) {
                SendClose();
                return;
            }
            boost::asio::write(upstream_, boost::asio::buffer(decrypted));
            break;
        }
        }
    }

    void WriteFrame(const std::vector<uint8_t>& frame)
    {
        std::lock_guard<std::mutex> lock(writeMutex_);
        boost::asio::write(stream_, boost::asio::buffer(frame));
    }

    void SendClose()
    {
        if (!open_) return;
        open_ = false;
        std::lock_guard<std::mutex> lock(writeMutex_);
        auto frame = framer_.Wrap({}, 0x8);
        boost::system::error_code ec;
        boost::asio::write(stream_, boost::asio::buffer(frame), ec);
        stream_.lowest_layer().close(ec);
        upstream_.close(ec);
    }

    void SendPong(const std::vector<uint8_t>& data)
    {
        auto frame = framer_.Wrap(data, 0xA);
        WriteFrame(frame);
    }
};

class WebSocketGateway {
public:
    explicit WebSocketGateway(const GatewayConfig& cfg)
        : io_(), acceptor_(io_), sslContext_(boost::asio::ssl::context::tls_server), config_(cfg)
    {
        if (config_.useTls) {
            if (config_.certificateFile.empty() || config_.privateKeyFile.empty()) {
                throw std::runtime_error("TLS enabled but certificate or key path is empty");
            }
            sslContext_.use_certificate_chain_file(config_.certificateFile);
            sslContext_.use_private_key_file(config_.privateKeyFile, boost::asio::ssl::context::pem);
        }
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
    boost::asio::ssl::context sslContext_;
    GatewayConfig config_;

    void AcceptLoop()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                if (config_.useTls) {
                    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sslStream(std::move(socket), sslContext_);
                    std::make_shared<WebSocketSession<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>>(std::move(sslStream), config_, io_)->Start();
                } else {
                    std::make_shared<WebSocketSession<boost::asio::ip::tcp::socket>>(std::move(socket), config_, io_)->Start();
                }
            }
            AcceptLoop();
        });
    }
};
} // namespace

int main(int argc, char* argv[])
{
    GatewayConfig cfg;
    cfg = LoadConfigFromFile("gateway.ini", cfg);
    if (argc > 1) {
        cfg.port = static_cast<uint16_t>(std::stoi(argv[1]));
    }
    if (argc > 2) {
        cfg.maxPayload = static_cast<size_t>(std::stoul(argv[2]));
    }
    if (argc > 3) {
        cfg.upstreamHost = argv[3];
    }
    if (argc > 4) {
        cfg.upstreamPort = static_cast<uint16_t>(std::stoi(argv[4]));
    }
    if (argc > 5) {
        cfg.encryptionKey = HexToBytes(argv[5]);
    }
    if (argc > 6) {
        cfg.useTls = std::string(argv[6]) == "1" || std::string(argv[6]) == "true";
    }
    if (argc > 7) {
        cfg.certificateFile = argv[7];
    }
    if (argc > 8) {
        cfg.privateKeyFile = argv[8];
    }
    if (cfg.encryptionKey.size() != 32) {
        std::cerr << "encryption_key must be 32 bytes of hex for AES-256-GCM; refusing to start gateway" << std::endl;
        return 1;
    }
    WebSocketGateway gateway(cfg);
    gateway.Run();
    return 0;
}


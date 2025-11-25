#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <thread>
#include <type_traits>
#include <vector>

#include "common/aes_gcm.h"
#include "common/websocket_frame.h"

#include <boost/asio.hpp>
#include <openssl/sha.h>
#include <boost/asio/ssl.hpp>
#include <openssl/rand.h>

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

std::map<std::string, std::string> ParseHeaders(const std::string& request)
{
    std::map<std::string, std::string> headers;
    std::istringstream iss(request);
    std::string line;
    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        name.erase(std::remove_if(name.begin(), name.end(), ::isspace), name.end());
        value.erase(0, value.find_first_not_of(" \t"));
        auto end = value.find_last_not_of(" \r\n\t");
        if (end != std::string::npos) value = value.substr(0, end + 1);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        headers[name] = value;
    }
    return headers;
}

std::string BytesToHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    for (auto b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

struct GatewayConfig {
    std::string bindAddress = "0.0.0.0";
    uint16_t port = 24443;
    size_t maxPayload = 1 << 20;
    std::string upstreamHost = "127.0.0.1";
    uint16_t upstreamPort = 6543;
    enum class TlsMode { EdgeTerminated, Enforced };
    TlsMode tlsMode = TlsMode::EdgeTerminated;
    std::string certificateFile;
    std::string privateKeyFile;
    std::vector<uint8_t> encryptionKey;
    std::string authToken;
    std::string allowedOrigin;
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
        else if (key == "use_tls") cfg.tlsMode = (value == "1" || value == "true" || value == "TRUE")
                ? GatewayConfig::TlsMode::Enforced
                : GatewayConfig::TlsMode::EdgeTerminated;
        else if (key == "tls_mode") {
            std::string lowered = value;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
            if (lowered == "enforced") cfg.tlsMode = GatewayConfig::TlsMode::Enforced;
            else cfg.tlsMode = GatewayConfig::TlsMode::EdgeTerminated;
        }
        else if (key == "certificate") cfg.certificateFile = value;
        else if (key == "private_key") cfg.privateKeyFile = value;
        else if (key == "auth_token") cfg.authToken = value;
        else if (key == "allowed_origin") cfg.allowedOrigin = value;
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
    std::condition_variable frameCv_;
    std::deque<std::vector<uint8_t>> pendingFrames_;
    bool writerActive_ = false;
    bool open_;
    DerivedSessionKey sessionKey_{};
    uint64_t clientToServerSeq_ = 0;
    uint64_t serverToClientSeq_ = 0;
    std::unordered_set<uint64_t> seenClientNonces_;
    uint64_t highestClientSeq_ = 0;
    std::unordered_set<uint64_t> seenServerNonces_;
    uint64_t highestServerSeq_ = 0;

    bool PerformTransportHandshake()
    {
        if constexpr (std::is_same_v<Stream, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>) {
            stream_.set_verify_mode(boost::asio::ssl::verify_peer);
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
            StartWriter();
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
        auto headers = ParseHeaders(request);
        if (request.find("Upgrade: websocket") == std::string::npos) {
            SendHttpError("400", "Missing upgrade header");
            return false;
        }
        auto keyIt = headers.find("sec-websocket-key");
        if (keyIt == headers.end()) { SendHttpError("400", "Missing Sec-WebSocket-Key"); return false; }
        std::string key = keyIt->second;
        key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());

        if (!config_.allowedOrigin.empty()) {
            auto originIt = headers.find("origin");
            if (originIt == headers.end() || originIt->second != config_.allowedOrigin) {
                SendHttpError("403", "Origin rejected");
                return false;
            }
        }
        if (!config_.authToken.empty()) {
            auto protoIt = headers.find("sec-websocket-protocol");
            if (protoIt == headers.end() || protoIt->second != config_.authToken) {
                SendHttpError("401", "Auth token missing or mismatched");
                return false;
            }
        }

        std::vector<uint8_t> clientNonce;
        auto nonceIt = headers.find("x-sr-client-nonce");
        if (nonceIt != headers.end()) {
            clientNonce = HexToBytes(nonceIt->second);
        }
        if (clientNonce.size() < 16) {
            SendHttpError("400", "Client nonce missing or invalid");
            return false;
        }
        std::vector<uint8_t> serverNonce(16);
        RAND_bytes(serverNonce.data(), static_cast<int>(serverNonce.size()));

        sessionKey_ = DeriveSessionKey(config_.encryptionKey, clientNonce, serverNonce);
        if (sessionKey_.key.size() != 32) {
            SendHttpError("500", "Unable to derive session key");
            return false;
        }

        const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string acceptSrc = key + magic;
        unsigned char sha1Hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(acceptSrc.data()), acceptSrc.size(), sha1Hash);
        std::string accept = base64_encode(sha1Hash, SHA_DIGEST_LENGTH);

        std::ostringstream resp;
        resp << "HTTP/1.1 101 Switching Protocols\r\n"
             << "Upgrade: websocket\r\n"
             << "Connection: Upgrade\r\n"
             << "Sec-WebSocket-Accept: " << accept << "\r\n";
        if (!config_.authToken.empty()) {
            resp << "Sec-WebSocket-Protocol: " << config_.authToken << "\r\n";
        }
        resp << "X-SR-Server-Nonce: " << BytesToHex(serverNonce) << "\r\n\r\n";
        auto responseStr = resp.str();
        boost::asio::write(stream_, boost::asio::buffer(responseStr));
        return true;
    }

    void SendHttpError(const std::string& status, const std::string& message)
    {
        std::ostringstream resp;
        resp << "HTTP/1.1 " << status << " Error\r\nContent-Type: text/plain\r\nContent-Length: " << message.size()
             << "\r\nConnection: close\r\n\r\n" << message;
        boost::system::error_code ec;
        boost::asio::write(stream_, boost::asio::buffer(resp.str()), ec);
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
                    if (!AesGcmEncrypt(self->sessionKey_.key, payload, encrypted,
                                       AeadDirection::ServerToClient, &self->serverToClientSeq_,
                                       &self->sessionKey_.salt, &self->seenServerNonces_, &self->highestServerSeq_)) {
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
            std::vector<uint8_t> payload;
            payload.reserve(static_cast<size_t>(std::min<uint64_t>(payloadLen, 4096)));
            uint64_t remaining = payloadLen;
            std::array<uint8_t, 4096> chunk{};
            while (remaining > 0) {
                auto step = static_cast<size_t>(std::min<uint64_t>(remaining, chunk.size()));
                boost::asio::read(stream_, boost::asio::buffer(chunk.data(), step));
                payload.insert(payload.end(), chunk.begin(), chunk.begin() + step);
                remaining -= step;
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
            if (!AesGcmDecrypt(sessionKey_.key, frame.payload, decrypted,
                               AeadDirection::ClientToServer, &sessionKey_.salt,
                               &seenClientNonces_, &highestClientSeq_)) {
                SendClose();
                return;
            }
            boost::asio::write(upstream_, boost::asio::buffer(decrypted));
            break;
        }
        }
    }

    void StartWriter()
    {
        if (writerActive_) return;
        writerActive_ = true;
        auto self = this->shared_from_this();
        std::thread([self]() {
            std::unique_lock<std::mutex> lk(self->writeMutex_);
            while (self->open_ || !self->pendingFrames_.empty()) {
                self->frameCv_.wait(lk, [&]() { return !self->pendingFrames_.empty() || !self->open_; });
                while (!self->pendingFrames_.empty()) {
                    auto frame = std::move(self->pendingFrames_.front());
                    self->pendingFrames_.pop_front();
                    lk.unlock();
                    boost::system::error_code ec;
                    boost::asio::write(self->stream_, boost::asio::buffer(frame), ec);
                    lk.lock();
                    if (ec) {
                        self->open_ = false;
                        break;
                    }
                    self->frameCv_.notify_all();
                }
            }
        }).detach();
    }

    void WriteFrame(const std::vector<uint8_t>& frame)
    {
        const size_t kMaxQueueDepth = 64;
        std::unique_lock<std::mutex> lock(writeMutex_);
        frameCv_.wait(lock, [&]() { return pendingFrames_.size() < kMaxQueueDepth || !open_; });
        pendingFrames_.push_back(frame);
        frameCv_.notify_all();
    }

    void SendClose()
    {
        std::unique_lock<std::mutex> lock(writeMutex_);
        if (!open_) return;
        open_ = false;
        auto frame = framer_.Wrap({}, 0x8);
        boost::system::error_code ec;
        boost::asio::write(stream_, boost::asio::buffer(frame), ec);
        stream_.lowest_layer().close(ec);
        upstream_.close(ec);
        frameCv_.notify_all();
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
        if (config_.tlsMode == GatewayConfig::TlsMode::Enforced) {
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
                if (config_.tlsMode == GatewayConfig::TlsMode::Enforced) {
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
        cfg.tlsMode = (std::string(argv[6]) == "1" || std::string(argv[6]) == "true")
            ? GatewayConfig::TlsMode::Enforced
            : GatewayConfig::TlsMode::EdgeTerminated;
    }
    if (argc > 7) {
        cfg.certificateFile = argv[7];
    }
    if (argc > 8) {
        cfg.privateKeyFile = argv[8];
    }
    if (argc > 9) {
        cfg.authToken = argv[9];
    }
    if (cfg.encryptionKey.size() != 32) {
        std::cerr << "encryption_key must be 32 bytes of hex for AES-256-GCM; refusing to start gateway" << std::endl;
        return 1;
    }
    if (cfg.authToken.empty()) {
        std::cerr << "auth_token must be configured to authenticate WebSocket upgrades" << std::endl;
        return 1;
    }
    if (cfg.allowedOrigin.empty()) {
        std::cerr << "allowed_origin must be set to enforce origin checks" << std::endl;
        return 1;
    }
    WebSocketGateway gateway(cfg);
    gateway.Run();
    return 0;
}


#include "aes_gcm.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    std::vector<uint8_t> out;
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) clean.push_back(c);
    }
    if (clean.size() % 2 != 0) return out;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        unsigned int byte = 0;
        std::istringstream iss(clean.substr(i, 2));
        iss >> std::hex >> byte;
        if (iss.fail()) {
            out.clear();
            return out;
        }
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

namespace {
constexpr size_t kNonceSize = 12;
constexpr size_t kTagSize = 16;
constexpr size_t kKeySize = 32;

bool HkdfExpand(const std::vector<uint8_t>& masterKey,
                const std::vector<uint8_t>& salt,
                const std::string& info,
                std::vector<uint8_t>& out)
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return false;

    bool ok = true;
    if (ok && EVP_PKEY_derive_init(pctx) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_set1_hkdf_key(pctx, masterKey.data(), static_cast<int>(masterKey.size())) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) <= 0) ok = false;
    size_t outLen = out.size();
    if (ok && EVP_PKEY_derive(pctx, out.data(), &outLen) <= 0) ok = false;

    EVP_PKEY_CTX_free(pctx);
    return ok;
}

std::array<uint8_t, kNonceSize> DeriveNonce(const std::array<uint8_t, kNonceSize>& salt,
                                            uint64_t seq)
{
    std::array<uint8_t, kNonceSize> nonce{};
    for (size_t i = 0; i < kNonceSize; ++i) nonce[i] = salt[i];
    for (int i = 0; i < 8; ++i) {
        nonce[kNonceSize - 1 - i] ^= static_cast<uint8_t>((seq >> (i * 8)) & 0xFF);
    }
    return nonce;
}

std::vector<uint8_t> BuildAad(AesGcmDirection dir, uint64_t seq)
{
    std::vector<uint8_t> aad;
    aad.reserve(1 + sizeof(uint64_t));
    aad.push_back(dir == AesGcmDirection::kClientToServer ? 0x01 : 0x02);
    for (int i = 7; i >= 0; --i) {
        aad.push_back(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF));
    }
    return aad;
}
} // namespace

bool InitializeAesGcmSession(const std::vector<uint8_t>& masterKey,
                             const std::vector<uint8_t>& clientNonce,
                             const std::vector<uint8_t>& serverNonce,
                             AesGcmSession& session)
{
    if (masterKey.size() != kKeySize) {
        std::cerr << "encryption key must be 32 bytes for AES-256-GCM" << std::endl;
        return false;
    }
    if (clientNonce.size() != kKeySize || serverNonce.size() != kKeySize) {
        std::cerr << "client/server nonces must be 32 bytes" << std::endl;
        return false;
    }

    std::vector<uint8_t> salt;
    salt.reserve(clientNonce.size() + serverNonce.size());
    salt.insert(salt.end(), clientNonce.begin(), clientNonce.end());
    salt.insert(salt.end(), serverNonce.begin(), serverNonce.end());

    std::vector<uint8_t> derived(kKeySize + 2 * kNonceSize);
    if (!HkdfExpand(masterKey, salt, "SimpleRemoter-WSS-Session", derived)) return false;

    session.sessionKey.assign(derived.begin(), derived.begin() + kKeySize);
    std::copy(derived.begin() + kKeySize, derived.begin() + kKeySize + kNonceSize, session.clientSalt.begin());
    std::copy(derived.begin() + kKeySize + kNonceSize, derived.end(), session.serverSalt.begin());
    session.clientSeq = 0;
    session.serverSeq = 0;
    session.seenClientSeq.clear();
    session.seenServerSeq.clear();
    session.initialized = true;
    return true;
}

bool AesGcmEncrypt(AesGcmSession& session,
                   AesGcmDirection direction,
                   std::vector<uint8_t> plaintext,
                   std::vector<uint8_t>& out)
{
    if (!session.initialized) {
        std::cerr << "AES-GCM session not initialized" << std::endl;
        return false;
    }

    uint64_t& seq = direction == AesGcmDirection::kClientToServer ? session.clientSeq : session.serverSeq;
    auto salt = direction == AesGcmDirection::kClientToServer ? session.clientSalt : session.serverSalt;
    auto nonce = DeriveNonce(salt, seq);
    auto aad = BuildAad(direction, seq);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int len = 0;
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, kTagSize> tag{};

    if (ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1) ok = false;
    if (ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, session.sessionKey.data(), nonce.data()) != 1) ok = false;
    if (ok && !aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ok = false;
    if (ok && EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) ok = false;
    int ciphertextLen = len;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) ok = false;
    ciphertextLen += len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data()) != 1) ok = false;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    out.clear();
    out.reserve(kNonceSize + sizeof(uint64_t) + ciphertextLen + kTagSize);
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&seq), reinterpret_cast<uint8_t*>(&seq) + sizeof(uint64_t));
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
    out.insert(out.end(), tag.begin(), tag.end());
    ++seq;
    return true;
}

bool AesGcmDecrypt(AesGcmSession& session,
                   AesGcmDirection direction,
                   const std::vector<uint8_t>& cipher,
                   std::vector<uint8_t>& plain)
{
    if (!session.initialized) {
        std::cerr << "AES-GCM session not initialized" << std::endl;
        return false;
    }
    if (cipher.size() < sizeof(uint64_t) + kNonceSize + kTagSize) {
        std::cerr << "ciphertext too small" << std::endl;
        return false;
    }

    uint64_t seq = 0;
    memcpy(&seq, cipher.data(), sizeof(uint64_t));

    auto& seen = direction == AesGcmDirection::kClientToServer ? session.seenClientSeq : session.seenServerSeq;
    if (!seen.insert(seq).second) {
        std::cerr << "duplicate nonce/sequence detected" << std::endl;
        return false;
    }

    auto salt = direction == AesGcmDirection::kClientToServer ? session.clientSalt : session.serverSalt;
    auto expectedNonce = DeriveNonce(salt, seq);

    const uint8_t* nonce = cipher.data() + sizeof(uint64_t);
    if (!std::equal(expectedNonce.begin(), expectedNonce.end(), nonce)) {
        std::cerr << "nonce mismatch for sequence" << std::endl;
        return false;
    }

    size_t cipherLen = cipher.size() - sizeof(uint64_t) - kNonceSize - kTagSize;
    const uint8_t* ciphertext = cipher.data() + sizeof(uint64_t) + kNonceSize;
    const uint8_t* tag = cipher.data() + sizeof(uint64_t) + kNonceSize + cipherLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int len = 0;
    plain.resize(cipherLen);
    auto aad = BuildAad(direction, seq);

    if (ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, session.sessionKey.data(), nonce) != 1) ok = false;
    if (ok && !aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ok = false;
    if (ok && EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext, static_cast<int>(cipherLen)) != 1) ok = false;
    int plainLen = len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag)) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) != 1) ok = false;
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    plain.resize(plainLen);
    return true;
}

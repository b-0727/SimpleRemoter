#include "aes_gcm.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <unordered_set>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

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

static DerivedSessionKey DeriveInternal(const std::vector<uint8_t>& masterKey,
                                        const std::vector<uint8_t>& clientNonce,
                                        const std::vector<uint8_t>& serverNonce,
                                        const unsigned char* info,
                                        size_t infoLen)
{
    DerivedSessionKey derived{};
    if (masterKey.size() != 32) {
        std::cerr << "master key must be 32 bytes to derive session material" << std::endl;
        return derived;
    }

    std::vector<uint8_t> salt;
    salt.reserve(clientNonce.size() + serverNonce.size());
    salt.insert(salt.end(), clientNonce.begin(), clientNonce.end());
    salt.insert(salt.end(), serverNonce.begin(), serverNonce.end());

    std::array<uint8_t, 36> okm{}; // 32 key + 4-byte salt for deterministic nonce prefix
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return derived;

    auto cleanup = [&]() {
        EVP_PKEY_CTX_free(pctx);
    };

    bool ok = true;
    if (EVP_PKEY_derive_init(pctx) != 1) ok = false;
    if (ok && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) != 1) ok = false;
    if (ok && !salt.empty() && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) != 1) ok = false;
    if (ok && EVP_PKEY_CTX_set1_hkdf_key(pctx, masterKey.data(), static_cast<int>(masterKey.size())) != 1) ok = false;
    if (ok && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(infoLen)) != 1) ok = false;
    size_t outLen = okm.size();
    if (ok && EVP_PKEY_derive(pctx, okm.data(), &outLen) != 1) ok = false;
    cleanup();
    if (!ok || outLen < okm.size()) {
        std::cerr << "hkdf derivation failed" << std::endl;
        return derived;
    }

    derived.key.assign(okm.begin(), okm.begin() + 32);
    std::copy(okm.begin() + 32, okm.end(), derived.salt.begin());
    return derived;
}

DerivedSessionKey DeriveSessionKey(const std::vector<uint8_t>& masterKey,
                                   const std::vector<uint8_t>& clientNonce,
                                   const std::vector<uint8_t>& serverNonce)
{
    static const unsigned char info[] = "simple-remoter-wss-session";
    return DeriveInternal(masterKey, clientNonce, serverNonce, info, sizeof(info) - 1);
}

DerivedSessionKey DeriveUpstreamSessionKey(const std::vector<uint8_t>& masterKey,
                                           const std::vector<uint8_t>& clientNonce,
                                           const std::vector<uint8_t>& serverNonce)
{
    static const unsigned char info[] = "simple-remoter-upstream-session";
    return DeriveInternal(masterKey, clientNonce, serverNonce, info, sizeof(info) - 1);
}

std::vector<uint8_t> ComputeNonceAuth(const std::vector<uint8_t>& masterKey,
                                      const std::vector<uint8_t>& clientNonce,
                                      const std::vector<uint8_t>& serverNonce,
                                      const std::string& token)
{
    std::vector<uint8_t> proof;
    if (masterKey.size() != 32) return proof;
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) return proof;
    auto cleanup = [&]() { HMAC_CTX_free(ctx); };
    bool ok = HMAC_Init_ex(ctx, masterKey.data(), static_cast<int>(masterKey.size()), EVP_sha256(), nullptr) == 1;
    if (ok && !clientNonce.empty()) ok = HMAC_Update(ctx, clientNonce.data(), clientNonce.size()) == 1;
    if (ok && !serverNonce.empty()) ok = HMAC_Update(ctx, serverNonce.data(), serverNonce.size()) == 1;
    if (ok && !token.empty()) ok = HMAC_Update(ctx, reinterpret_cast<const uint8_t*>(token.data()), token.size()) == 1;
    unsigned int len = 0;
    proof.resize(EVP_MAX_MD_SIZE);
    if (ok && HMAC_Final(ctx, proof.data(), &len) == 1) {
        proof.resize(len);
    } else {
        proof.clear();
    }
    cleanup();
    return proof;
}

static std::array<uint8_t, 12> BuildNonce(const std::array<uint8_t, 4>& salt, uint64_t seq)
{
    std::array<uint8_t, 12> nonce{};
    std::copy(salt.begin(), salt.end(), nonce.begin());
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<uint8_t>((seq >> (56 - i * 8)) & 0xFF);
    }
    return nonce;
}

static bool CheckAndRecordNonce(uint64_t seq,
                                std::unordered_set<uint64_t>* seenNonces,
                                uint64_t* highestSeen,
                                size_t window = 256)
{
    if (!seenNonces || !highestSeen) return true; // best-effort tracking only when provided
    if (seenNonces->count(seq)) {
        return false; // duplicate replay
    }
    seenNonces->insert(seq);
    if (seq > *highestSeen) {
        *highestSeen = seq;
        // Drop stale sequence numbers outside the sliding window to cap memory
        std::set<uint64_t> ordered(seenNonces->begin(), seenNonces->end());
        while (ordered.size() > window) {
            auto it = ordered.begin();
            seenNonces->erase(*it);
            ordered.erase(it);
        }
    }
    return true;
}

bool AesGcmEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& out,
                   AeadDirection direction, uint64_t* sequence, const std::array<uint8_t, 4>* nonceSalt,
                   std::unordered_set<uint64_t>* seenNonces, uint64_t* highestSeen)
{
    if (key.empty()) {
        out = plaintext;
        return true;
    }
    if (key.size() != 32) {
        std::cerr << "encryption key must be 32 bytes for AES-256-GCM" << std::endl;
        return false;
    }

    static uint64_t fallbackSeq = 0;
    uint64_t seq = sequence ? ++(*sequence) : ++fallbackSeq;
    std::array<uint8_t, 12> nonce = nonceSalt ? BuildNonce(*nonceSalt, seq) : [&]() {
        std::array<uint8_t, 12> n{};
        RAND_bytes(n.data(), static_cast<int>(n.size()));
        return n;
    }();

    if (!CheckAndRecordNonce(seq, seenNonces, highestSeen)) {
        std::cerr << "duplicate nonce detected during encrypt" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int len = 0;
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag{};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) ok = false;
    if (ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) ok = false;
    uint8_t aad[9];
    aad[0] = static_cast<uint8_t>(direction);
    for (int i = 0; i < 8; ++i) aad[1 + i] = static_cast<uint8_t>((seq >> (56 - i * 8)) & 0xFF);
    if (ok && EVP_EncryptUpdate(ctx, nullptr, &len, aad, sizeof(aad)) != 1) ok = false;
    if (ok && EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) ok = false;
    int ciphertextLen = len;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) ok = false;
    ciphertextLen += len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) ok = false;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    out.clear();
    out.reserve(nonce.size() + ciphertextLen + tag.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
    out.insert(out.end(), tag.begin(), tag.end());
    return true;
}

bool AesGcmDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain,
                   AeadDirection direction, const std::array<uint8_t, 4>* nonceSalt,
                   std::unordered_set<uint64_t>* seenNonces, uint64_t* highestSeen)
{
    if (key.empty()) {
        plain = cipher;
        return true;
    }
    if (key.size() != 32) {
        std::cerr << "encryption key must be 32 bytes for AES-256-GCM" << std::endl;
        return false;
    }
    if (cipher.size() < 12 + 16) {
        std::cerr << "ciphertext too small" << std::endl;
        return false;
    }
    const uint8_t* nonce = cipher.data();
    uint64_t seq = 0;
    for (int i = 0; i < 8; ++i) {
        seq = (seq << 8) | nonce[4 + i];
    }
    if (nonceSalt && !std::equal(nonceSalt->begin(), nonceSalt->end(), nonce)) {
        std::cerr << "nonce salt mismatch; rejecting replay" << std::endl;
        return false;
    }
    if (!CheckAndRecordNonce(seq, seenNonces, highestSeen)) {
        std::cerr << "duplicate nonce detected during decrypt" << std::endl;
        return false;
    }
    size_t cipherLen = cipher.size() - 12 - 16;
    const uint8_t* ciphertext = cipher.data() + 12;
    const uint8_t* tag = cipher.data() + 12 + cipherLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int len = 0;
    plain.resize(cipherLen);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) ok = false;
    uint8_t aad[9];
    aad[0] = static_cast<uint8_t>(direction);
    for (int i = 0; i < 8; ++i) aad[1 + i] = static_cast<uint8_t>((seq >> (56 - i * 8)) & 0xFF);
    if (ok && EVP_DecryptUpdate(ctx, nullptr, &len, aad, sizeof(aad)) != 1) ok = false;
    if (ok && EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext, static_cast<int>(cipherLen)) != 1) ok = false;
    int plainLen = len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) != 1) ok = false;
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    plain.resize(plainLen);
    return true;
}

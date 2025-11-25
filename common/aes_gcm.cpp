#include "aes_gcm.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
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

bool AesGcmEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& out)
{
    if (key.empty()) {
        out = plaintext;
        return true;
    }
    if (key.size() != 32) {
        std::cerr << "encryption key must be 32 bytes for AES-256-GCM" << std::endl;
        return false;
    }

    std::array<uint8_t, 12> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        std::cerr << "failed to generate nonce" << std::endl;
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

bool AesGcmDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain)
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

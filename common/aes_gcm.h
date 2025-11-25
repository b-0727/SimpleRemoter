#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>
#include <unordered_set>
#include <vector>

// Directional AAD flag to bind ciphertext to a specific flow.
enum class AeadDirection : uint8_t {
    ClientToServer = 0x01,
    ServerToClient = 0x02,
};

struct DerivedSessionKey {
    std::vector<uint8_t> key;      // 32-byte AES-256 key
    std::array<uint8_t, 4> salt;   // Nonce salt used to construct deterministic IVs
};

// Convert a hexadecimal string (whitespace ignored) into raw bytes. Returns
// an empty vector on parse failure.
std::vector<uint8_t> HexToBytes(const std::string& hex);

// Derive a per-session AES-256-GCM key using HKDF-SHA256. The master key must
// be 32 bytes. Client and server nonces are mixed into the salt to ensure
// uniqueness per connection, keeping the master key only in hex form on disk.
DerivedSessionKey DeriveSessionKey(const std::vector<uint8_t>& masterKey,
                                   const std::vector<uint8_t>& clientNonce,
                                   const std::vector<uint8_t>& serverNonce);

// AES-256-GCM encryption helpers. When the key is empty, payloads are
// forwarded unmodified so operators can disable the extra protection while
// keeping the same transport code path.
bool AesGcmEncrypt(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& plaintext,
                   std::vector<uint8_t>& out,
                   AeadDirection direction = AeadDirection::ClientToServer,
                   uint64_t* sequence = nullptr,
                   const std::array<uint8_t, 4>* nonceSalt = nullptr,
                   std::unordered_set<uint64_t>* seenNonces = nullptr,
                   uint64_t* highestSeen = nullptr);

bool AesGcmDecrypt(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& cipher,
                   std::vector<uint8_t>& plain,
                   AeadDirection direction = AeadDirection::ClientToServer,
                   const std::array<uint8_t, 4>* nonceSalt = nullptr,
                   std::unordered_set<uint64_t>* seenNonces = nullptr,
                   uint64_t* highestSeen = nullptr);

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

// Convert a hexadecimal string (whitespace ignored) into raw bytes. Returns
// an empty vector on parse failure.
std::vector<uint8_t> HexToBytes(const std::string& hex);

// AES-256-GCM with session-level derivation and replay-resistant sequencing.
// Clients and servers perform an HKDF over the shared master key and a pair
// of nonces exchanged during the WebSocket handshake to produce per-session
// keys and per-direction nonce salts. Each encrypted record carries AAD that
// binds direction and monotonically increasing sequence numbers so duplicate
// nonces are rejected.

enum class AesGcmDirection {
    kClientToServer,
    kServerToClient,
};

struct AesGcmSession {
    std::vector<uint8_t> sessionKey;
    std::array<uint8_t, 12> clientSalt{};
    std::array<uint8_t, 12> serverSalt{};
    uint64_t clientSeq = 0;
    uint64_t serverSeq = 0;
    std::unordered_set<uint64_t> seenClientSeq;
    std::unordered_set<uint64_t> seenServerSeq;

    bool initialized = false;
};

// Derive a per-session key and nonce salts using HKDF-SHA256. Returns false if
// the master key is not 32 bytes or HKDF fails.
bool InitializeAesGcmSession(const std::vector<uint8_t>& masterKey,
                             const std::vector<uint8_t>& clientNonce,
                             const std::vector<uint8_t>& serverNonce,
                             AesGcmSession& session);

// Encrypt/decrypt with per-session sequencing and AAD. Direction selects the
// nonce salt and sequence counter to use.
bool AesGcmEncrypt(AesGcmSession& session,
                   AesGcmDirection direction,
                   std::vector<uint8_t> plaintext,
                   std::vector<uint8_t>& out);

bool AesGcmDecrypt(AesGcmSession& session,
                   AesGcmDirection direction,
                   const std::vector<uint8_t>& cipher,
                   std::vector<uint8_t>& plain);

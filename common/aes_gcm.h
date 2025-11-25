#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Convert a hexadecimal string (whitespace ignored) into raw bytes. Returns
// an empty vector on parse failure.
std::vector<uint8_t> HexToBytes(const std::string& hex);

// AES-256-GCM encryption helpers. When the key is empty, payloads are
// forwarded unmodified so operators can disable the extra protection while
// keeping the same transport code path.
bool AesGcmEncrypt(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& plaintext,
                   std::vector<uint8_t>& out);

bool AesGcmDecrypt(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& cipher,
                   std::vector<uint8_t>& plain);

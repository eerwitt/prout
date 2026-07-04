// Thin wrappers over Monocypher for the two primitives the vault needs:
//   - a passphrase -> 32-byte key derivation (Argon2id), and
//   - authenticated encryption of a blob (XChaCha20-Poly1305).
// Also exposes BLAKE2b for the audit hash chain.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "common/secure_mem.h"

namespace prout {

inline constexpr int kKeyBytes = 32;
inline constexpr int kSaltBytes = 16;
inline constexpr int kNonceBytes = 24;
inline constexpr int kMacBytes = 16;
inline constexpr int kBlake2bBytes = 32;

// Argon2id parameters. Tuned for interactive unlock (~a few hundred ms), not a
// password-hashing server. nb_blocks is in KiB blocks: 65536 -> 64 MiB.
struct KdfParams {
  std::uint32_t nb_blocks = 65536;
  std::uint32_t nb_passes = 3;
  std::uint32_t nb_lanes = 1;
};

// Fills `salt` with cryptographically secure random bytes.
absl::Status RandomBytes(std::uint8_t *out, std::size_t n);

// Derives a 32-byte key from a passphrase + salt into locked memory.
absl::StatusOr<SecureBuffer> DeriveKey(const std::string &passphrase,
                                       const std::uint8_t salt[kSaltBytes],
                                       const KdfParams &params);

// Encrypts `plaintext` under `key`. Output layout: nonce(24) | mac(16) |
// cipher.
absl::StatusOr<std::vector<std::uint8_t>>
AeadSeal(const SecureBuffer &key, const std::uint8_t *plaintext, std::size_t n);

// Decrypts a blob produced by AeadSeal into locked memory.
absl::StatusOr<SecureBuffer> AeadOpen(const SecureBuffer &key,
                                      const std::uint8_t *blob, std::size_t n);

// BLAKE2b-256 of a byte range, hex-encoded. Used for the audit chain.
std::string Blake2bHex(const std::string &data);
std::string Blake2bHex(const std::string &prev_hex, const std::string &record);

// Hex helpers.
std::string ToHex(const std::uint8_t *p, std::size_t n);
absl::StatusOr<std::vector<std::uint8_t>> FromHex(const std::string &hex);

} // namespace prout

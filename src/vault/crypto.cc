#include "vault/crypto.h"

#include <cstring>
#include <vector>

extern "C" {
#include "monocypher.h"
}

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cerrno>
#include <cstdio>
#endif

namespace prout {

absl::Status RandomBytes(std::uint8_t *out, std::size_t n) {
#if defined(_WIN32)
  NTSTATUS s = ::BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                                 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (s != 0)
    return absl::InternalError("BCryptGenRandom failed");
  return absl::OkStatus();
#else
  std::FILE *f = std::fopen("/dev/urandom", "rb");
  if (!f)
    return absl::InternalError("cannot open /dev/urandom");
  std::size_t got = std::fread(out, 1, n, f);
  std::fclose(f);
  if (got != n)
    return absl::InternalError("short read from /dev/urandom");
  return absl::OkStatus();
#endif
}

absl::StatusOr<SecureBuffer> DeriveKey(const std::string &passphrase,
                                       const std::uint8_t salt[kSaltBytes],
                                       const KdfParams &params) {
  // work_area must be nb_blocks * 1024 bytes.
  std::vector<std::uint8_t> work(static_cast<std::size_t>(params.nb_blocks) *
                                 1024);
  SecureBuffer key(kKeyBytes);

  crypto_argon2_config cfg;
  cfg.algorithm = CRYPTO_ARGON2_ID;
  cfg.nb_blocks = params.nb_blocks;
  cfg.nb_passes = params.nb_passes;
  cfg.nb_lanes = params.nb_lanes;

  crypto_argon2_inputs in;
  in.pass = reinterpret_cast<const std::uint8_t *>(passphrase.data());
  in.pass_size = static_cast<std::uint32_t>(passphrase.size());
  in.salt = salt;
  in.salt_size = kSaltBytes;

  crypto_argon2(key.data(), kKeyBytes, work.data(), cfg, in,
                crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());
  return key;
}

absl::StatusOr<std::vector<std::uint8_t>>
AeadSeal(const SecureBuffer &key, const std::uint8_t *plaintext,
         std::size_t n) {
  if (key.size() != kKeyBytes)
    return absl::InternalError("bad key size");
  std::vector<std::uint8_t> out(kNonceBytes + kMacBytes + n);
  std::uint8_t *nonce = out.data();
  std::uint8_t *mac = out.data() + kNonceBytes;
  std::uint8_t *cipher = out.data() + kNonceBytes + kMacBytes;
  auto st = RandomBytes(nonce, kNonceBytes);
  if (!st.ok())
    return st;
  crypto_aead_lock(cipher, mac, key.data(), nonce, /*ad=*/nullptr, 0, plaintext,
                   n);
  return out;
}

absl::StatusOr<SecureBuffer> AeadOpen(const SecureBuffer &key,
                                      const std::uint8_t *blob, std::size_t n) {
  if (key.size() != kKeyBytes)
    return absl::InternalError("bad key size");
  if (n < kNonceBytes + kMacBytes)
    return absl::InvalidArgumentError("ciphertext too short");
  const std::uint8_t *nonce = blob;
  const std::uint8_t *mac = blob + kNonceBytes;
  const std::uint8_t *cipher = blob + kNonceBytes + kMacBytes;
  std::size_t clen = n - kNonceBytes - kMacBytes;
  SecureBuffer out(clen);
  int rc = crypto_aead_unlock(out.data(), mac, key.data(), nonce,
                              /*ad=*/nullptr, 0, cipher, clen);
  if (rc != 0)
    return absl::PermissionDeniedError(
        "vault decryption failed (wrong passphrase or tampered file)");
  return out;
}

static std::string HexOf(const std::uint8_t *p, std::size_t n) {
  static const char *kHex = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    s[2 * i] = kHex[p[i] >> 4];
    s[2 * i + 1] = kHex[p[i] & 0xf];
  }
  return s;
}

std::string ToHex(const std::uint8_t *p, std::size_t n) { return HexOf(p, n); }

absl::StatusOr<std::vector<std::uint8_t>> FromHex(const std::string &hex) {
  if (hex.size() % 2 != 0)
    return absl::InvalidArgumentError("odd hex length");
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  std::vector<std::uint8_t> out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return absl::InvalidArgumentError("bad hex digit");
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return out;
}

std::string Blake2bHex(const std::string &data) {
  std::uint8_t h[kBlake2bBytes];
  crypto_blake2b(h, kBlake2bBytes,
                 reinterpret_cast<const std::uint8_t *>(data.data()),
                 data.size());
  return HexOf(h, kBlake2bBytes);
}

std::string Blake2bHex(const std::string &prev_hex, const std::string &record) {
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, kBlake2bBytes);
  crypto_blake2b_update(&ctx,
                        reinterpret_cast<const std::uint8_t *>(prev_hex.data()),
                        prev_hex.size());
  crypto_blake2b_update(&ctx,
                        reinterpret_cast<const std::uint8_t *>(record.data()),
                        record.size());
  std::uint8_t h[kBlake2bBytes];
  crypto_blake2b_final(&ctx, h);
  return HexOf(h, kBlake2bBytes);
}

} // namespace prout

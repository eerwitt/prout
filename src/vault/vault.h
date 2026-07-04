// The encrypted credential store. On disk it is a single XChaCha20-Poly1305
// blob keyed by an Argon2id passphrase derivation; in memory the decrypted
// credentials live in locked SecureBuffers. Each service carries the policy the
// arbiter reasons against and the ceilings code clamps lease terms to.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "common/secure_mem.h"
#include "vault/crypto.h"

namespace prout {

enum class Disclosure { kInject, kReveal };

std::string DisclosureName(Disclosure d);
absl::StatusOr<Disclosure> ParseDisclosure(const std::string &s);

// Hard ceilings + free-text guidance for one service. The model may propose
// anything; code never grants beyond max_ttl_seconds / max_uses.
struct Policy {
  std::uint32_t max_ttl_seconds = 900;
  std::uint32_t max_uses = 3;
  std::string description; // what the credential is (safe to show the model)
  std::string guidance;    // free-text steer for the arbiter
};

struct Service {
  std::string name;
  std::string inject_env; // e.g. GITHUB_TOKEN
  Disclosure disclosure = Disclosure::kInject;
  Policy policy;
  std::string website_url;
  std::string website_host;
  std::string company;
  std::string details;
  std::string expires_at;
  std::string created_at;
  std::string updated_at;
  std::vector<std::string> update_timestamps;
  SecureBuffer credential; // decrypted secret, locked in memory
};

class Vault {
public:
  // Loads and decrypts <dir>/vault.json with `passphrase`.
  static absl::StatusOr<Vault> Open(const std::string &dir,
                                    const std::string &passphrase);
  // Creates a fresh empty vault in `dir`, encrypted under `passphrase`.
  static absl::Status Init(const std::string &dir,
                           const std::string &passphrase);

  // Re-encrypts and writes the vault back to disk.
  absl::Status Save() const;

  // Adds or replaces a service, then persists. `credential` is consumed.
  absl::Status AddService(Service service, SecureBuffer credential);

  // Edits an existing service, then persists. If `credential` is non-null it is
  // consumed and replaces the old credential.
  absl::Status EditService(const std::string &name, const Service &updates,
                           const SecureBuffer *credential);

  absl::Status DeleteService(const std::string &name);

  std::vector<std::string> ServiceNames() const;
  const Service *Find(const std::string &name) const;

  const std::string &dir() const { return dir_; }

private:
  Vault() = default;

  std::string dir_;
  KdfParams kdf_;
  std::array<std::uint8_t, kSaltBytes> salt_{};
  SecureBuffer key_; // derived key, kept to allow Save() without re-prompting
  std::map<std::string, Service> services_;
};

} // namespace prout

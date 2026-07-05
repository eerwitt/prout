// The encrypted credential store. On disk it is an append-only set of
// per-machine vault-<machine>.jsonl logs keyed by an Argon2id passphrase
// derivation. Each encrypted mutation is hash-chained inside its machine log,
// then all logs are replayed into the effective in-memory vault state.
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

struct VaultHistoryEntry {
  std::string revision_id;
  std::string machine;
  std::string timestamp;
  std::string action;
  std::string service;
  std::vector<std::string> fields;
  bool active = false;
};

class Vault {
public:
  // Loads, verifies, decrypts, and replays <dir>/vault-*.jsonl.
  static absl::StatusOr<Vault> Open(const std::string &dir,
                                    const std::string &passphrase);
  // Creates a fresh empty vault log in `dir`, encrypted under `passphrase`.
  static absl::Status Init(const std::string &dir,
                           const std::string &passphrase);

  // Verifies every vault log without exposing credential values.
  static absl::Status Verify(const std::string &dir,
                             const std::string &passphrase);

  // Adds a service, then appends metadata, policy, and credential revisions.
  // `credential` is consumed.
  absl::Status AddService(Service service, SecureBuffer credential);

  // Edits metadata/policy only, then appends changed field revisions.
  absl::Status EditService(const std::string &name, const Service &updates);

  // Appends a credential-only revision.
  absl::Status RotateService(const std::string &name, SecureBuffer credential);

  absl::Status DeleteService(const std::string &name);

  std::vector<std::string> ServiceNames() const;
  const Service *Find(const std::string &name) const;
  std::vector<VaultHistoryEntry> History(const std::string &name) const;

  const std::string &dir() const { return dir_; }

private:
  Vault() = default;
  friend absl::StatusOr<Vault> OpenInternal(const std::string &dir,
                                            const std::string &passphrase,
                                            bool replay);

  std::string dir_;
  KdfParams kdf_;
  std::array<std::uint8_t, kSaltBytes> salt_{};
  SecureBuffer key_; // derived key, kept to allow Save() without re-prompting
  std::map<std::string, Service> services_;
  std::vector<VaultHistoryEntry> history_;
};

} // namespace prout

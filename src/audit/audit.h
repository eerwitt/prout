// Append-only, hash-chained audit log. Each machine writes only to its own
// file (audit-<machine>.jsonl), so syncing the vault directory is a conflict-
// free union. Credential VALUES are never recorded -- only who asked, why, and
// what was granted.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace prout {

struct AuditEntry {
  std::string conversation_id;
  std::string event;
  std::string agent;
  std::string service;
  std::string intent;
  std::string details;
  std::string command_summary;
  std::string transcript; // short summary of the negotiation
  std::string verdict;    // "granted" | "denied" | "question"
  std::string rationale;  // model's stated reason (no secrets)
  std::uint32_t ttl_seconds = 0;
  std::uint32_t max_uses = 0;
  std::string disclosure; // "inject" | "reveal" | ""
  int child_exit_code = -1;
  bool redacted = false;
  std::string prout_error;
};

class AuditLog {
public:
  explicit AuditLog(std::string dir);

  // Appends one record, chaining it to the last hash in this machine's file.
  absl::Status Append(const AuditEntry &e);

  // Returns the last `n` records (newest last) as pretty one-line strings.
  absl::StatusOr<std::vector<std::string>> Tail(int n) const;

  // Returns safe metadata for one conversation, newest first.
  absl::StatusOr<std::vector<std::string>>
  Conversation(const std::string &conversation_id) const;

  // Recomputes the chain over this machine's file; error if broken.
  absl::Status Verify() const;

private:
  std::string Path() const;
  std::string dir_;
  std::string machine_;
};

} // namespace prout

// The arbiter drives the on-device Gemma model through LiteRT-LM's Conversation
// C ABI to negotiate lease terms. It owns the engine (loaded once, kept warm)
// and one conversation per in-flight negotiation, so multi-turn discussion is
// just successive messages on the same conversation.
//
// The model only ever RECOMMENDS: every proposed lease is clamped to the
// service policy ceilings in ProposeVerdict before it leaves this class, and a
// malformed or missing response degrades to a question, then a denial.
#pragma once

#include <map>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "arbiter/verdict.h"
#include "vault/vault.h"

namespace prout {

// Opaque holder for the LiteRT-LM handles + per-negotiation conversations,
// so this header stays free of the C ABI.
class ArbiterBackend;

class Arbiter {
public:
  // Loads `model_path` (a .litertlm file) on the given backend ("cpu"/"gpu").
  // If model_path is empty, a deterministic heuristic backend is used instead
  // (no inference) -- useful for testing the full flow without the ~1GB model.
  static absl::StatusOr<std::unique_ptr<Arbiter>>
  Create(const std::string &model_path, const std::string &backend = "cpu");

  ~Arbiter();

  // Starts a negotiation for `service` given the agent's `intent` and optional
  // command. On a question, `*negotiation_id` is set so the caller can resume
  // with Reply.
  Verdict Begin(const Service &service, const std::string &agent,
                const std::string &intent, const std::string &command_summary,
                std::string *negotiation_id);

  // Continues negotiation `id` with the agent's answer. Returns a denial if the
  // id is unknown or the question budget is exhausted.
  Verdict Reply(const std::string &negotiation_id, const std::string &answer);

  bool using_model() const;

private:
  explicit Arbiter(std::unique_ptr<ArbiterBackend> backend);
  std::unique_ptr<ArbiterBackend> backend_;
};

// Parses a raw model JSON response and clamps any proposed lease to policy.
// Exposed for unit reasoning/tests. On unparseable input returns a denial.
Verdict ProposeVerdict(const std::string &raw_json, const Policy &policy);

} // namespace prout

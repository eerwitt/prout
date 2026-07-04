// The arbiter's structured output and the lease it can produce. Kept free of
// any LiteRT-LM types so the daemon and tests can use it without the engine.
#pragma once

#include <cstdint>
#include <string>

namespace prout {

// What the arbiter decided for one negotiation turn.
struct Verdict {
  enum class Type { kQuestion, kLease, kDeny };
  Type type = Type::kDeny;

  // kQuestion: a follow-up the agent must answer.
  std::string question;

  // kLease: the (already clamped) terms.
  std::uint32_t ttl_seconds = 0;
  std::uint32_t max_uses = 0;

  // Human-readable reason, safe to log and show the agent.
  std::string rationale;

  static Verdict Question(std::string q) {
    Verdict v;
    v.type = Type::kQuestion;
    v.question = std::move(q);
    return v;
  }
  static Verdict Lease(std::uint32_t ttl, std::uint32_t uses, std::string why) {
    Verdict v;
    v.type = Type::kLease;
    v.ttl_seconds = ttl;
    v.max_uses = uses;
    v.rationale = std::move(why);
    return v;
  }
  static Verdict Deny(std::string why) {
    Verdict v;
    v.type = Type::kDeny;
    v.rationale = std::move(why);
    return v;
  }
};

} // namespace prout

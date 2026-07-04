#include "arbiter/arbiter.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "nlohmann/json.hpp"

extern "C" {
#include "c/engine.h"
}

namespace prout {
using json = nlohmann::json;

namespace {

std::uint32_t Clamp(std::uint32_t v, std::uint32_t lo, std::uint32_t hi) {
  return v < lo ? lo : (v > hi ? hi : v);
}

// Extracts the first balanced {...} JSON object embedded in `text`, ignoring
// braces inside strings. Small models often wrap JSON in prose or fences.
std::string FirstJsonObject(const std::string &text) {
  int depth = 0;
  bool in_str = false, esc = false;
  std::size_t start = std::string::npos;
  for (std::size_t i = 0; i < text.size(); ++i) {
    char c = text[i];
    if (in_str) {
      if (esc)
        esc = false;
      else if (c == '\\')
        esc = true;
      else if (c == '"')
        in_str = false;
      continue;
    }
    if (c == '"') {
      in_str = true;
      continue;
    }
    if (c == '{') {
      if (depth == 0)
        start = i;
      ++depth;
    } else if (c == '}') {
      if (depth > 0 && --depth == 0 && start != std::string::npos)
        return text.substr(start, i - start + 1);
    }
  }
  return std::string();
}

// The assistant response arrives as a dumped message object. Pull out the text.
std::string ExtractAssistantText(const std::string &dump) {
  json j = json::parse(dump, nullptr, false);
  if (j.is_discarded())
    return dump;
  if (j.is_string())
    return j.get<std::string>();
  std::function<std::string(const json &)> walk =
      [&](const json &n) -> std::string {
    if (n.is_string())
      return n.get<std::string>();
    std::string out;
    if (n.is_object()) {
      if (n.contains("text") && n["text"].is_string())
        return n["text"].get<std::string>();
      if (n.contains("content"))
        return walk(n["content"]);
      for (auto &[k, v] : n.items())
        out += walk(v);
    } else if (n.is_array()) {
      for (const auto &e : n)
        out += walk(e);
    }
    return out;
  };
  std::string t = walk(j);
  return t.empty() ? dump : t;
}

std::string BuildSystemPrompt(const Service &s) {
  const Policy &p = s.policy;
  std::ostringstream o;
  o << "You are Prout, an on-device credential-lease arbiter. An AI agent "
       "wants "
       "to use a stored credential. Your job is to grant a SHORT-LIVED lease "
       "with a sensible time-to-live and use-count based on WHY the agent says "
       "it needs the credential. Granting is the normal outcome; only deny if "
       "the stated intent is contradictory, clearly abusive, or makes no sense "
       "for this credential.\n\n";
  o << "CREDENTIAL: " << (p.description.empty() ? s.name : p.description)
    << "\n";
  o << "POLICY CEILINGS (you cannot exceed these; the system clamps you): "
    << "max_ttl_seconds=" << p.max_ttl_seconds << ", max_uses=" << p.max_uses
    << "\n";
  if (!p.guidance.empty())
    o << "OWNER GUIDANCE: " << p.guidance << "\n";
  o << "\nRespond with EXACTLY ONE JSON object and nothing else. One of:\n"
       "  {\"type\":\"lease\",\"ttl_seconds\":<int>,\"max_uses\":<int>,"
       "\"rationale\":\"<one sentence>\"}\n"
       "  {\"type\":\"question\",\"question\":\"<one short question>\"}\n"
       "  {\"type\":\"deny\",\"rationale\":\"<one sentence>\"}\n"
       "Ask a question only if the intent is too vague to size a lease. Prefer "
       "the smallest ttl and use-count that fit the task.";
  return o.str();
}

std::string UserMessageJson(const std::string &text) {
  json m = {{"role", "user"},
            {"content", json::array({{{"type", "text"}, {"text", text}}})}};
  return m.dump();
}

} // namespace

Verdict ProposeVerdict(const std::string &raw, const Policy &policy) {
  if (policy.max_ttl_seconds == 0 || policy.max_uses == 0)
    return Verdict::Deny("service policy has zero lease ceiling");

  std::string obj = FirstJsonObject(raw);
  if (obj.empty())
    return Verdict::Deny("arbiter returned no parseable verdict");
  json j = json::parse(obj, nullptr, false);
  if (j.is_discarded())
    return Verdict::Deny("arbiter verdict was not valid JSON");

  std::string type = j.value("type", "");

  if (type == "question") {
    std::string q =
        j.value("question", "Can you clarify what you need this for?");
    return Verdict::Question(q);
  }
  if (type == "deny") {
    return Verdict::Deny(j.value("rationale", "denied by arbiter"));
  }
  if (type == "lease") {
    std::uint32_t ttl = Clamp(j.value("ttl_seconds", policy.max_ttl_seconds),
                              1u, policy.max_ttl_seconds);
    std::uint32_t uses = Clamp(j.value("max_uses", 1u), 1u, policy.max_uses);
    std::string why = j.value("rationale", "intent accepted");
    return Verdict::Lease(ttl, uses, why);
  }
  return Verdict::Deny("arbiter verdict had unknown type");
}
// ---------------------------------------------------------------------------
// Backend interface + two implementations.
// ---------------------------------------------------------------------------
class ArbiterBackend {
public:
  virtual ~ArbiterBackend() = default;
  virtual Verdict Begin(const Service &, const std::string &agent,
                        const std::string &intent, std::string *nid) = 0;
  virtual Verdict Reply(const std::string &nid, const std::string &answer) = 0;
  virtual bool using_model() const = 0;
};

namespace {
std::string NewId() {
  static std::atomic<std::uint64_t> counter{0};
  return "neg-" + std::to_string(++counter);
}
constexpr int kMaxQuestions = 2;
} // namespace

// --- LiteRT-LM backed arbiter ---------------------------------------------
class LiteRtBackend : public ArbiterBackend {
public:
  explicit LiteRtBackend(LiteRtLmEngine *engine) : engine_(engine) {}
  ~LiteRtBackend() override {
    for (auto &[id, n] : negotiations_)
      if (n.conv)
        litert_lm_conversation_delete(n.conv);
    if (engine_)
      litert_lm_engine_delete(engine_);
  }

  Verdict Begin(const Service &s, const std::string & /*agent*/,
                const std::string &intent, std::string *nid) override {
    std::string id = NewId();
    Neg n;
    n.policy = s.policy;
    n.conv = CreateConversation(BuildSystemPrompt(s));
    if (!n.conv)
      return Verdict::Deny("arbiter failed to start a conversation");
    negotiations_.emplace(id, std::move(n));
    return Advance(id, intent, nid);
  }

  Verdict Reply(const std::string &nid, const std::string &answer) override {
    if (negotiations_.find(nid) == negotiations_.end())
      return Verdict::Deny("unknown or expired negotiation id");
    std::string same = nid;
    return Advance(nid, answer, &same);
  }

  bool using_model() const override { return true; }

private:
  struct Neg {
    Policy policy;
    int questions = 0;
    LiteRtLmConversation *conv = nullptr;
  };

  LiteRtLmConversation *CreateConversation(const std::string &system_prompt) {
    LiteRtLmSamplerParams *sampler =
        litert_lm_sampler_params_create(kLiteRtLmSamplerTypeGreedy);
    LiteRtLmSessionConfig *sess = litert_lm_session_config_create();
    litert_lm_session_config_set_sampler_params(sess, sampler);
    litert_lm_session_config_set_max_output_tokens(sess, 256);
    LiteRtLmConversationConfig *cfg = litert_lm_conversation_config_create();
    litert_lm_conversation_config_set_session_config(cfg, sess);
    std::string sys = json({{"type", "text"}, {"text", system_prompt}}).dump();
    litert_lm_conversation_config_set_system_message(cfg, sys.c_str());
    LiteRtLmConversation *conv = litert_lm_conversation_create(engine_, cfg);
    litert_lm_conversation_config_delete(cfg);
    litert_lm_session_config_delete(sess);
    litert_lm_sampler_params_delete(sampler);
    return conv;
  }

  // Sends one turn on the negotiation `id`, decides, and manages the question
  // budget + conversation lifetime. `*nid` is left as `id` so a follow-up
  // question reuses the same negotiation id.
  Verdict Advance(const std::string &id, const std::string &user_text,
                  std::string *nid) {
    Neg &n = negotiations_.at(id);
    std::string msg = UserMessageJson(user_text);
    LiteRtLmJsonResponse *resp = litert_lm_conversation_send_message(
        n.conv, msg.c_str(), /*extra_context=*/nullptr,
        /*optional_args=*/nullptr);
    Verdict v = Verdict::Deny("arbiter produced no response");
    if (resp) {
      const char *s = litert_lm_json_response_get_string(resp);
      std::string text = s ? ExtractAssistantText(s) : std::string();
      litert_lm_json_response_delete(resp);
      v = ProposeVerdict(text, n.policy);
    }

    if (v.type == Verdict::Type::kQuestion && ++n.questions <= kMaxQuestions) {
      *nid = id;
      return v;
    }
    if (v.type == Verdict::Type::kQuestion)
      v = Verdict::Deny(
          "could not establish a clear enough intent to grant a lease");
    if (n.conv)
      litert_lm_conversation_delete(n.conv);
    negotiations_.erase(id);
    return v;
  }

  LiteRtLmEngine *engine_ = nullptr;
  std::map<std::string, Neg> negotiations_;
};

// --- Heuristic (no-model) arbiter -----------------------------------------
// Deterministic stand-in so the full lease/audit/run flow can be exercised
// without downloading the model. It is intentionally simple and clearly not a
// substitute for the Gemma reasoning it mimics.
class HeuristicBackend : public ArbiterBackend {
public:
  Verdict Begin(const Service &s, const std::string &,
                const std::string &intent, std::string *nid) override {
    std::string t = Lower(intent);
    int words = CountWords(intent);
    if (words < 4 && !asked_once_) {
      asked_once_ = true;
      std::string id = NewId();
      pending_[id] = s.policy;
      *nid = id;
      return Verdict::Question("What specifically will you do with this "
                               "credential, and for how long?");
    }
    return Decide(s.policy, t);
  }

  Verdict Reply(const std::string &nid, const std::string &answer) override {
    auto it = pending_.find(nid);
    if (it == pending_.end())
      return Verdict::Deny("unknown or expired negotiation id");
    Policy p = it->second;
    pending_.erase(it);
    return Decide(p, Lower(answer));
  }

  bool using_model() const override { return false; }

private:
  static std::string Lower(const std::string &s) {
    std::string o = s;
    for (char &c : o)
      c = static_cast<char>(std::tolower((unsigned char)c));
    return o;
  }
  static int CountWords(const std::string &s) {
    int n = 0;
    bool in = false;
    for (char c : s) {
      if (std::isspace((unsigned char)c))
        in = false;
      else if (!in) {
        in = true;
        ++n;
      }
    }
    return n;
  }
  static bool Has(const std::string &hay, const char *needle) {
    return hay.find(needle) != std::string::npos;
  }

  Verdict Decide(const Policy &p, const std::string &t) {
    if (Has(t, "something") || Has(t, "whatever") || t.size() < 8)
      return Verdict::Deny(
          "intent is too vague to size a credential lease (heuristic)");
    // Read-only / diagnostic intents get a tighter lease.
    bool readish = Has(t, "read") || Has(t, "select") || Has(t, "check") ||
                   Has(t, "verify") || Has(t, "list") || Has(t, "get");
    std::uint32_t ttl = readish
                            ? std::min<std::uint32_t>(300, p.max_ttl_seconds)
                            : p.max_ttl_seconds;
    std::uint32_t uses = readish ? std::min<std::uint32_t>(1, p.max_uses)
                                 : std::min<std::uint32_t>(2, p.max_uses);
    if (uses == 0)
      uses = 1;
    return Verdict::Lease(ttl, uses,
                          std::string(readish ? "read-only" : "write") +
                              " intent accepted (heuristic)");
  }

  bool asked_once_ = false;
  std::map<std::string, Policy> pending_;
};

// ---------------------------------------------------------------------------
Arbiter::Arbiter(std::unique_ptr<ArbiterBackend> b) : backend_(std::move(b)) {}
Arbiter::~Arbiter() = default;

absl::StatusOr<std::unique_ptr<Arbiter>>
Arbiter::Create(const std::string &model_path, const std::string &backend) {
  if (model_path.empty()) {
    return std::unique_ptr<Arbiter>(
        new Arbiter(std::make_unique<HeuristicBackend>()));
  }
  litert_lm_set_min_log_level(3); // WARNING+
  LiteRtLmEngineSettings *settings = litert_lm_engine_settings_create(
      model_path.c_str(), backend.c_str(), nullptr, nullptr);
  if (!settings)
    return absl::InternalError("failed to create engine settings for " +
                               model_path);
  LiteRtLmEngine *engine = litert_lm_engine_create(settings);
  litert_lm_engine_settings_delete(settings);
  if (!engine)
    return absl::InternalError(
        "failed to load model (bad path or unsupported file?): " + model_path);
  return std::unique_ptr<Arbiter>(
      new Arbiter(std::make_unique<LiteRtBackend>(engine)));
}

Verdict Arbiter::Begin(const Service &s, const std::string &agent,
                       const std::string &intent, std::string *nid) {
  return backend_->Begin(s, agent, intent, nid);
}
Verdict Arbiter::Reply(const std::string &nid, const std::string &answer) {
  return backend_->Reply(nid, answer);
}
bool Arbiter::using_model() const { return backend_->using_model(); }

} // namespace prout

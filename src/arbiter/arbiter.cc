#include "arbiter/arbiter.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

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
  o << "You are Prout's credential-lease arbiter. Decide whether the requested "
       "command should receive a short-lived lease for the stored credential. "
       "Do not perform the task. Do not ask for or handle the credential "
       "value.\n\n";
  o << "Stored credential description: "
    << (p.description.empty() ? s.name : p.description) << "\n";
  o << "Policy ceilings (code clamps these): max_ttl_seconds="
    << p.max_ttl_seconds << ", max_uses=" << p.max_uses << "\n";
  if (!p.guidance.empty())
    o << "Owner guidance: " << p.guidance << "\n";
  o << "\nDecision rules:\n"
       "- Grant concrete, benign requests that use this credential for this "
       "service.\n"
       "- Grant read-only or diagnostic requests against the service's own "
       "host, including authenticated/private account reads, unless a deny "
       "rule applies.\n"
       "- Inspect the whole requested_command, not just the first action. "
       "Check commands after ';', '&&', pipes, redirects, subshells, and "
       "nested shell -Command strings.\n"
       "- Ask a question only when one missing fact prevents sizing or judging "
       "the lease.\n"
       "- Deny only for a concrete blocker: unrelated host/service, credential "
       "exfiltration, destructive work not justified by the intent, abusive "
       "use, contradiction between intent and command, impossible use, or "
       "nonsensical request.\n"
       "- Treat printing, echoing, logging, copying, saving, uploading, or "
       "otherwise revealing the credential or its delivery environment "
       "variable as credential exfiltration. Using the credential only in an "
       "Authorization header to the service host is not exfiltration.\n"
       "- Do not deny because you cannot access websites or APIs.\n\n"
       "Rationale rules:\n"
       "- Grant rationale: name the allowed use and lease size reason.\n"
       "- Question text: ask only for the missing fact needed to decide.\n"
       "- Deny rationale: state the specific blocking rule and the evidence "
       "from the intent or command.\n"
       "- Never use a rationale that only repeats or summarizes the request.\n\n"
       "Call exactly one registered tool: grant_lease, ask_question, or "
       "deny_request. If tool calling is unavailable, respond with EXACTLY "
       "ONE JSON object and "
       "nothing else using one of these shapes:\n"
       "  {\"type\":\"lease\",\"ttl_seconds\":<int>,\"max_uses\":<int>,"
       "\"rationale\":\"<one sentence>\"}\n"
       "  {\"type\":\"question\",\"question\":\"<one short question>\"}\n"
       "  {\"type\":\"deny\",\"rationale\":\"<one sentence>\"}\n"
       "Prefer the smallest ttl and use-count that fit the task.";
  return o.str();
}

std::string InitialUserText(const Service &s, const std::string &agent,
                            const std::string &intent,
                            const std::string &command_summary) {
  std::ostringstream o;
  o << "Lease request metadata:\n";
  o << "requester_agent_name=" << agent << "\n";
  o << "service=" << s.name << "\n";
  if (!s.website_host.empty())
    o << "service_host=" << s.website_host << "\n";
  if (!s.website_url.empty())
    o << "service_url=" << s.website_url << "\n";
  if (!s.company.empty())
    o << "company=" << s.company << "\n";
  if (!s.inject_env.empty())
    o << "credential_delivery_env_var=" << s.inject_env << "\n";
  o << "disclosure=" << DisclosureName(s.disclosure) << "\n";
  o << "intent=" << intent << "\n\n";
  if (!command_summary.empty())
    o << "requested_command=" << command_summary << "\n\n";
  o << "Notes: requester_agent_name is only the caller label. "
       "credential_delivery_env_var is where Prout injects the credential if "
       "a lease is granted. A command that prints or stores that variable "
       "must be denied as credential exfiltration. Decide the lease only.";
  return o.str();
}

std::string UserMessageJson(const std::string &text) {
  json m = {{"role", "user"},
            {"content", json::array({{{"type", "text"}, {"text", text}}})}};
  return m.dump();
}

std::string ArbiterToolsJson() {
  json string_schema = {{"type", "string"}, {"maxLength", 240}};
  json int_schema = {{"type", "integer"}, {"minimum", 1}};

  json grant_params = {
      {"type", "object"},
      {"properties",
       {{"ttl_seconds", int_schema},
        {"max_uses", int_schema},
        {"rationale", string_schema}}},
      {"required", json::array({"ttl_seconds", "max_uses", "rationale"})}};
  json question_params = {
      {"type", "object"},
      {"properties",
       {{"question", string_schema}, {"rationale", string_schema}}},
      {"required", json::array({"question"})}};
  json deny_params = {{"type", "object"},
                      {"properties", {{"rationale", string_schema}}},
                      {"required", json::array({"rationale"})}};

  json grant = {
      {"type", "function"},
      {"function",
       {{"name", "grant_lease"},
        {"description",
         "Grant a lease. Rationale must name the allowed use and lease size "
         "reason."},
        {"parameters", grant_params}}}};
  json question = {
      {"type", "function"},
      {"function",
       {{"name", "ask_question"},
        {"description",
         "Ask one concise follow-up question naming only the missing fact "
         "needed to decide."},
        {"parameters", question_params}}}};
  json deny = {
      {"type", "function"},
      {"function",
       {{"name", "deny_request"},
        {"description", "Deny only when the requested credential use is "
                        "unsafe, impossible, contradictory, nonsensical, "
                        "unrelated to the service, or otherwise blocked. The "
                        "rationale must name the blocking rule and evidence, "
                        "not summarize the request. Printing or dumping the "
                        "credential env var is credential exfiltration."},
        {"parameters", deny_params}}}};
  return json::array({grant, question, deny}).dump();
}
std::string JsonStringValue(const json &j, const char *key,
                            const std::string &fallback = std::string()) {
  if (!j.is_object() || !j.contains(key))
    return fallback;
  const json &v = j[key];
  if (v.is_string())
    return v.get<std::string>();
  return fallback;
}

bool JsonUintValue(const json &j, const char *key, std::uint32_t *out) {
  if (!j.is_object() || !j.contains(key))
    return false;
  const json &v = j[key];
  if (v.is_number_unsigned()) {
    *out = v.get<std::uint32_t>();
    return *out > 0;
  }
  if (v.is_number_integer()) {
    auto i = v.get<std::int64_t>();
    if (i <= 0)
      return false;
    *out = static_cast<std::uint32_t>(i);
    return true;
  }
  return false;
}

bool FindToolCalls(const json &node, const json **calls) {
  if (node.is_object()) {
    auto it = node.find("tool_calls");
    if (it != node.end() && it->is_array()) {
      *calls = &*it;
      return true;
    }
    for (const auto &[_, v] : node.items()) {
      if (FindToolCalls(v, calls))
        return true;
    }
  } else if (node.is_array()) {
    for (const auto &v : node) {
      if (FindToolCalls(v, calls))
        return true;
    }
  }
  return false;
}

json ToolArguments(const json &function) {
  if (!function.is_object() || !function.contains("arguments"))
    return json::object();
  const json &args = function["arguments"];
  if (args.is_object())
    return args;
  if (args.is_string()) {
    json parsed = json::parse(args.get<std::string>(), nullptr, false);
    if (parsed.is_object())
      return parsed;
  }
  return json::object();
}

std::string CompactRationale(const std::string &text) {
  std::string out;
  out.reserve(std::min<std::size_t>(text.size(), 240));
  bool last_space = true;
  int sentences = 0;
  for (char c : text) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::isspace(uc)) {
      if (!last_space) {
        out.push_back(' ');
        last_space = true;
      }
      continue;
    }
    out.push_back(c);
    last_space = false;
    if (c == '.' || c == '!' || c == '?') {
      ++sentences;
      if (sentences >= 2)
        break;
    }
    if (out.size() >= 240) {
      out.resize(237);
      out += "...";
      break;
    }
  }
  while (!out.empty() && out.back() == ' ')
    out.pop_back();
  return out.empty() ? "denied by arbiter" : out;
}

Verdict ProposeToolCallVerdict(const std::string &raw, const Policy &policy,
                               bool *found_tool_call) {
  *found_tool_call = false;
  json root = json::parse(raw, nullptr, false);
  if (root.is_discarded())
    return Verdict::Deny("arbiter response was not valid JSON");
  const json *calls = nullptr;
  if (!FindToolCalls(root, &calls))
    return Verdict::Deny("arbiter returned no tool call");
  *found_tool_call = true;
  if (calls->empty())
    return Verdict::Deny("arbiter returned empty tool call list");

  const json &tool = calls->front();
  if (!tool.is_object() || !tool.contains("function") ||
      !tool["function"].is_object())
    return Verdict::Deny("arbiter tool call was malformed");
  const json &function = tool["function"];
  std::string name = JsonStringValue(function, "name");
  json args = ToolArguments(function);

  if (name == "ask_question") {
    std::string q = JsonStringValue(args, "question");
    if (q.empty())
      return Verdict::Deny("arbiter question tool call omitted question");
    return Verdict::Question(q);
  }
  if (name == "deny_request") {
    std::string rationale =
        JsonStringValue(args, "rationale", "denied by arbiter");
    return Verdict::Deny(CompactRationale(rationale));
  }
  if (name == "grant_lease") {
    std::uint32_t ttl = 0;
    std::uint32_t uses = 0;
    if (!JsonUintValue(args, "ttl_seconds", &ttl))
      ttl = policy.max_ttl_seconds;
    if (!JsonUintValue(args, "max_uses", &uses))
      uses = 1;
    ttl = Clamp(ttl, 1u, policy.max_ttl_seconds);
    uses = Clamp(uses, 1u, policy.max_uses);
    std::string rationale =
        JsonStringValue(args, "rationale", "intent accepted");
    return Verdict::Lease(ttl, uses, CompactRationale(rationale));
  }
  return Verdict::Deny("arbiter called unknown tool '" + name + "'");
}
bool IsParseFailure(const Verdict &v) {
  return v.type == Verdict::Type::kDeny &&
         (v.rationale == "arbiter returned no parseable verdict" ||
          v.rationale == "arbiter verdict was not valid JSON" ||
          v.rationale == "arbiter verdict had unknown type");
}

std::string LogSnippet(const std::string &text) {
  constexpr std::size_t kMaxSnippet = 800;
  std::string out;
  std::size_t n = std::min(text.size(), kMaxSnippet);
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    char c = text[i];
    if (c == '\n')
      out += "\\n";
    else if (c == '\r')
      out += "\\r";
    else if (c == '\t')
      out += "\\t";
    else
      out += c;
  }
  if (text.size() > kMaxSnippet)
    out += "...";
  return out;
}

void LogParseFailure(const char *phase, const Verdict &v,
                     const std::string &text) {
  std::string snippet = LogSnippet(text);
  std::fprintf(stderr, "prout: arbiter %s parse failed: %s; model_text=%s\n",
               phase, v.rationale.c_str(), snippet.c_str());
}

std::string RepairPrompt() {
  return "Your previous answer was not valid for Prout. Call exactly one "
         "registered tool: grant_lease, ask_question, or deny_request. If tool "
         "calling is unavailable, return exactly one JSON object and no prose, "
         "markdown, code fence, or explanation. You are deciding a credential "
         "lease only; do not deny because you cannot access websites or APIs, "
         "and do not ask for the credential value. Use one of these JSON "
         "fallback shapes: "
         "{\"type\":\"lease\",\"ttl_seconds\":300,\"max_uses\":1,"
         "\"rationale\":\"one sentence\"} or "
         "{\"type\":\"question\",\"question\":\"one short question\"} "
         "or {\"type\":\"deny\",\"rationale\":\"one sentence\"}.";
}

} // namespace

Verdict ProposeVerdict(const std::string &raw, const Policy &policy) {
  if (policy.max_ttl_seconds == 0 || policy.max_uses == 0)
    return Verdict::Deny("service policy has zero lease ceiling");

  bool found_tool_call = false;
  Verdict tool = ProposeToolCallVerdict(raw, policy, &found_tool_call);
  if (found_tool_call)
    return tool;

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
                        const std::string &intent,
                        const std::string &command_summary,
                        std::string *nid) = 0;
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

  Verdict Begin(const Service &s, const std::string &agent,
                const std::string &intent, const std::string &command_summary,
                std::string *nid) override {
    std::string id = NewId();
    Neg n;
    n.policy = s.policy;
    n.conv = CreateConversation(BuildSystemPrompt(s));
    if (!n.conv)
      return Verdict::Deny("arbiter failed to start a conversation");
    negotiations_.emplace(id, std::move(n));
    return Advance(id, InitialUserText(s, agent, intent, command_summary), nid);
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
        litert_lm_sampler_params_create(kLiteRtLmSamplerTypeTopP);
    litert_lm_sampler_params_set_top_k(sampler, 1);
    litert_lm_sampler_params_set_top_p(sampler, 1.0f);
    litert_lm_sampler_params_set_temperature(sampler, 0.1f);
    LiteRtLmSessionConfig *sess = litert_lm_session_config_create();
    litert_lm_session_config_set_sampler_params(sess, sampler);
    litert_lm_session_config_set_max_output_tokens(sess, 256);
    LiteRtLmConversationConfig *cfg = litert_lm_conversation_config_create();
    litert_lm_conversation_config_set_session_config(cfg, sess);
    litert_lm_conversation_config_set_enable_constrained_decoding(cfg, true);
    std::string tools = ArbiterToolsJson();
    litert_lm_conversation_config_set_tools(cfg, tools.c_str());
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
      std::string raw = s ? std::string(s) : std::string();
      std::string text = ExtractAssistantText(raw);
      litert_lm_json_response_delete(resp);
      v = ProposeVerdict(raw, n.policy);
      if (IsParseFailure(v))
        v = ProposeVerdict(text, n.policy);
      if (IsParseFailure(v)) {
        LogParseFailure("response", v, text);
        std::string repair = UserMessageJson(RepairPrompt());
        LiteRtLmJsonResponse *retry = litert_lm_conversation_send_message(
            n.conv, repair.c_str(), /*extra_context=*/nullptr,
            /*optional_args=*/nullptr);
        if (retry) {
          const char *rs = litert_lm_json_response_get_string(retry);
          std::string repaired_raw = rs ? std::string(rs) : std::string();
          std::string repaired_text = ExtractAssistantText(repaired_raw);
          litert_lm_json_response_delete(retry);
          v = ProposeVerdict(repaired_raw, n.policy);
          if (IsParseFailure(v))
            v = ProposeVerdict(repaired_text, n.policy);
          if (IsParseFailure(v))
            LogParseFailure("repair", v, repaired_text);
        }
      }
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
                const std::string &intent, const std::string &command_summary,
                std::string *nid) override {
    std::string t = Lower(intent);
    int words = CountWords(intent);
    if (words < 4 && !asked_once_) {
      asked_once_ = true;
      std::string id = NewId();
      pending_[id] = Pending{s.policy, s.website_host, command_summary};
      *nid = id;
      return Verdict::Question("What specifically will you do with this "
                               "credential, and for how long?");
    }
    return Decide(s, t, command_summary);
  }

  Verdict Reply(const std::string &nid, const std::string &answer) override {
    auto it = pending_.find(nid);
    if (it == pending_.end())
      return Verdict::Deny("unknown or expired negotiation id");
    Pending pending = it->second;
    pending_.erase(it);
    return Decide(pending.policy, pending.website_host, Lower(answer),
                  pending.command_summary);
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

  static std::vector<std::string> CommandHosts(const std::string &command) {
    std::vector<std::string> hosts;
    std::string lower = Lower(command);
    std::size_t pos = 0;
    while (true) {
      std::size_t http = lower.find("http://", pos);
      std::size_t https = lower.find("https://", pos);
      std::size_t start =
          std::min(http == std::string::npos ? lower.size() : http,
                   https == std::string::npos ? lower.size() : https);
      if (start == lower.size())
        break;
      start += lower.compare(start, 8, "https://") == 0 ? 8 : 7;
      std::size_t end = lower.find_first_of(" /?#'\"`)", start);
      std::string host =
          lower.substr(start, end == std::string::npos ? end : end - start);
      auto colon = host.find(':');
      if (colon != std::string::npos)
        host.erase(colon);
      while (!host.empty() && host.back() == '.')
        host.pop_back();
      if (!host.empty())
        hosts.push_back(host);
      if (end == std::string::npos)
        break;
      pos = end + 1;
    }
    return hosts;
  }

  static bool CommandTargetsServiceHost(const std::string &website_host,
                                        const std::string &command) {
    if (website_host.empty())
      return true;
    auto hosts = CommandHosts(command);
    if (hosts.empty())
      return true;
    std::string allowed = Lower(website_host);
    for (const auto &host : hosts) {
      if (host != allowed && !(host.size() > allowed.size() &&
                               host.compare(host.size() - allowed.size(),
                                            allowed.size(), allowed) == 0 &&
                               host[host.size() - allowed.size() - 1] == '.'))
        return false;
    }
    return true;
  }

  Verdict Decide(const Service &s, const std::string &t,
                 const std::string &command_summary) {
    return Decide(s.policy, s.website_host, t, command_summary);
  }

  Verdict Decide(const Policy &p, const std::string &website_host,
                 const std::string &t, const std::string &command_summary) {
    if (!CommandTargetsServiceHost(website_host, command_summary))
      return Verdict::Deny(
          "command targets a different website host than the service policy "
          "(heuristic)");
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
  struct Pending {
    Policy policy;
    std::string website_host;
    std::string command_summary;
  };
  std::map<std::string, Pending> pending_;
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
                       const std::string &intent,
                       const std::string &command_summary, std::string *nid) {
  return backend_->Begin(s, agent, intent, command_summary, nid);
}
Verdict Arbiter::Reply(const std::string &nid, const std::string &answer) {
  return backend_->Reply(nid, answer);
}
bool Arbiter::using_model() const { return backend_->using_model(); }

} // namespace prout

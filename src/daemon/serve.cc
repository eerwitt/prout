// The long-lived daemon: loads the vault + keeps Gemma warm, then serves
// negotiation requests over the AF_UNIX socket. Single-threaded and serialized
// -- one model, one user -- which keeps lease state trivially consistent.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <exception>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "arbiter/arbiter.h"
#include "audit/audit.h"
#include "cli/args.h"
#include "cli/commands.h"
#include "common/paths.h"
#include "common/prompt.h"
#include "common/secure_mem.h"
#include "daemon/lease.h"
#include "ipc/ipc.h"
#include "nlohmann/json.hpp"
#include "vault/crypto.h"
#include "vault/vault.h"

namespace prout {
using json = nlohmann::json;

namespace {

std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

std::string NewConversationId() {
  std::array<std::uint8_t, 32> bytes{};
  if (!RandomBytes(bytes.data(), bytes.size()).ok())
    return "conv-random-failed";
  return "conv-" + ToHex(bytes.data(), bytes.size());
}

std::string LeaseReason(LeaseTable::Status st) {
  switch (st) {
  case LeaseTable::Status::kUnknown:
    return "no such lease";
  case LeaseTable::Status::kExpired:
    return "lease expired";
  case LeaseTable::Status::kExhausted:
    return "lease fully used";
  case LeaseTable::Status::kWrongService:
    return "lease is for a different service";
  case LeaseTable::Status::kOk:
    return "";
  }
  return "lease denied";
}

struct Conversation {
  std::string id;
  std::string kind; // "run" or "expose"
  std::string service;
  std::string agent;
  std::string intent;
  std::string details;
  std::string arbiter_id;
  std::string rationale;
  std::string lease_id;
  std::vector<std::string> command;
  std::string command_summary;
  std::uint32_t ttl_seconds = 0;
  std::uint32_t max_uses = 0;
  std::uint32_t lease_uses_remaining = 0;
  bool approved = false;
  std::chrono::steady_clock::time_point expires_at;
};

class Daemon {
public:
  Daemon(Vault vault, std::unique_ptr<Arbiter> arbiter, std::string dir)
      : vault_(std::move(vault)), arbiter_(std::move(arbiter)),
        audit_(std::move(dir)) {}

  std::string Handle(const std::string &request) {
    try {
      json req = json::parse(request, nullptr, false);
      if (req.is_discarded())
        return Error("malformed request");
      std::string op = req.value("op", "");
      if (op == "ping")
        return json{{"status", "ok"}, {"model", arbiter_->using_model()}}
            .dump();
      if (op == "negotiate")
        return Negotiate(req);
      if (op == "continue")
        return Continue(req);
      if (op == "execute")
        return Execute(req);
      if (op == "execute_result")
        return ExecuteResult(req);
      if (op == "expose_final")
        return ExposeFinal(req);
      return Error("unknown op '" + op + "'");
    } catch (const std::exception &e) {
      return Error("request failed: " + std::string(e.what()));
    } catch (...) {
      return Error("request failed");
    }
  }

private:
  static std::string Error(const std::string &m) {
    return json{{"status", "error"}, {"message", m}}.dump();
  }

  absl::Status Audit(const AuditEntry &entry) { return audit_.Append(entry); }

  std::string AuditError(const absl::Status &st) {
    return Error("could not append audit record: " + std::string(st.message()));
  }

  std::string Deny(const Conversation &c, const std::string &rationale,
                   const std::string &event = "deny",
                   const std::string &command_summary = "") {
    auto st = Audit(AuditEntry{.conversation_id = c.id,
                               .event = event,
                               .agent = c.agent,
                               .service = c.service,
                               .intent = c.intent,
                               .details = c.details,
                               .command_summary = command_summary,
                               .transcript = Transcript(c),
                               .verdict = "denied",
                               .rationale = rationale});
    if (!st.ok())
      return AuditError(st);
    return json{{"status", "denied"},
                {"conversation_id", c.id},
                {"rationale", rationale}}
        .dump();
  }

  std::string Question(Conversation c, const std::string &question) {
    std::string old_id = c.id;
    c.id = NewConversationId();
    c.approved = false;
    c.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    conversations_[c.id] = c;
    conversations_.erase(old_id);
    auto st = Audit(AuditEntry{.conversation_id = c.id,
                               .event = "question",
                               .agent = c.agent,
                               .service = c.service,
                               .intent = c.intent,
                               .details = c.details,
                               .transcript = "question: " + question,
                               .verdict = "question",
                               .rationale = question});
    if (!st.ok())
      return AuditError(st);
    return json{{"status", "question"},
                {"conversation_id", c.id},
                {"question", question}}
        .dump();
  }

  std::string Grant(Conversation c, const Service &s, const Verdict &v) {
    if (s.policy.max_ttl_seconds == 0 || s.policy.max_uses == 0)
      return Deny(c, "service policy has zero lease ceiling");
    if (c.kind == "expose" && s.disclosure != Disclosure::kReveal)
      return Deny(c,
                  "service '" + s.name +
                      "' does not permit revealing its value; use `prout run`");
    c.id = NewConversationId();
    c.approved = true;
    c.rationale = v.rationale;
    c.ttl_seconds = v.ttl_seconds;
    c.max_uses = v.max_uses;
    c.expires_at =
        std::chrono::steady_clock::now() + std::chrono::seconds(v.ttl_seconds);
    auto lease_id_or = leases_.Create(c.service, c.ttl_seconds, c.max_uses);
    if (!lease_id_or.ok())
      return Error("could not create lease: " +
                   std::string(lease_id_or.status().message()));
    c.lease_id = *lease_id_or;
    conversations_[c.id] = c;
    lease_conversations_[c.lease_id] = c.id;
    auto st = Audit(AuditEntry{.conversation_id = c.id,
                               .event = "grant",
                               .agent = c.agent,
                               .service = c.service,
                               .intent = c.intent,
                               .details = c.details,
                               .command_summary = c.command_summary,
                               .transcript = Transcript(c),
                               .verdict = "granted",
                               .rationale = c.rationale,
                               .ttl_seconds = c.ttl_seconds,
                               .max_uses = c.max_uses,
                               .disclosure = DisclosureName(s.disclosure)});
    if (!st.ok())
      return AuditError(st);
    return json{
        {"status", "granted"},
        {"conversation_id", c.id},
        {"lease_id", c.lease_id},
        {"service", c.service},
        {"kind", c.kind},
        {"ttl_seconds", c.ttl_seconds},
        {"max_uses", c.max_uses},
        {"disclosure", DisclosureName(s.disclosure)},
        {"env_var", s.disclosure == Disclosure::kInject ? s.inject_env : ""},
        {"rationale", c.rationale}}
        .dump();
  }

  std::string Transcript(const Conversation &c) const {
    if (c.details.empty())
      return "intent: " + c.intent;
    return "intent: " + c.intent + " | details: " + c.details;
  }

  bool Expired(const Conversation &c) const {
    return std::chrono::steady_clock::now() >= c.expires_at;
  }

  const Service *FindServiceFresh(const std::string &name, std::string *error) {
    const Service *s = vault_.Find(name);
    if (s)
      return s;
    auto st = vault_.Reload();
    if (!st.ok()) {
      *error = std::string(st.message());
      return nullptr;
    }
    s = vault_.Find(name);
    if (!s) {
      *error = "unknown service '" + name + "'";
      return nullptr;
    }
    return s;
  }

  std::string DeliverCredential(const Conversation &c, const Service &s) {
    std::string credential(reinterpret_cast<const char *>(s.credential.data()),
                           s.credential.size());
    json r{
        {"status", "deliver"},     {"conversation_id", c.id},
        {"lease_id", c.lease_id},  {"command", c.command},
        {"service", c.service},    {"kind", c.kind},
        {"env_var", s.inject_env}, {"disclosure", DisclosureName(s.disclosure)},
        {"credential", credential}};
    std::string out = r.dump();
    SecureZero(credential.data(), credential.size());
    return out;
  }

  std::string Negotiate(const json &req) {
    Conversation c;
    c.id = NewConversationId();
    c.kind = req.value("kind", "run");
    c.service = req.value("service", "");
    c.agent = req.value("agent", "agent");
    c.intent = req.value("intent", "");
    c.command = req.value("command", std::vector<std::string>{});
    c.command_summary = req.value("command_summary", "");
    c.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    if (c.kind != "run" && c.kind != "expose")
      return Error("invalid conversation kind");
    std::string service_error;
    const Service *s = FindServiceFresh(c.service, &service_error);
    if (!s)
      return Error(service_error);
    if (c.intent.empty())
      return Error("missing intent");
    if (c.kind == "run" && c.command.empty())
      return Error("run requires a command after `--`");

    std::string arbiter_id;
    Verdict v =
        arbiter_->Begin(*s, c.agent, c.intent, c.command_summary, &arbiter_id);
    c.arbiter_id = arbiter_id;
    if (v.type == Verdict::Type::kQuestion)
      return Question(c, v.question);
    if (v.type == Verdict::Type::kDeny)
      return Deny(c, v.rationale);
    return Grant(c, *s, v);
  }

  std::string Continue(const json &req) {
    std::string id = req.value("conversation_id", "");
    auto it = conversations_.find(id);
    if (it == conversations_.end())
      return Error("unknown or expired conversation id '" + id + "'");
    Conversation c = it->second;
    conversations_.erase(it);
    if (Expired(c))
      return Deny(c, "conversation expired");
    if (c.approved)
      return Error("conversation is already approved");
    std::string kind = req.value("kind", c.kind);
    if (kind != c.kind)
      return Deny(c, "conversation kind mismatch");
    c.agent = req.value("agent", c.agent);
    c.details = req.value("details", "");
    if (c.details.empty())
      return Error("missing details");
    std::string service_error;
    const Service *s = FindServiceFresh(c.service, &service_error);
    if (!s)
      return Error(service_error);
    Verdict v = arbiter_->Reply(c.arbiter_id, c.details);
    if (v.type == Verdict::Type::kQuestion)
      return Question(c, v.question);
    if (v.type == Verdict::Type::kDeny)
      return Deny(c, v.rationale);
    return Grant(c, *s, v);
  }

  std::string Execute(const json &req) {
    std::string lease_id = req.value("lease_id", "");
    auto lease_it = lease_conversations_.find(lease_id);
    if (lease_it == lease_conversations_.end()) {
      Conversation c{.id = lease_id, .kind = "run", .lease_id = lease_id};
      return Deny(c, "no such lease", "execute");
    }
    std::string id = lease_it->second;
    auto it = conversations_.find(id);
    if (it == conversations_.end()) {
      lease_conversations_.erase(lease_it);
      Conversation c{.id = lease_id, .kind = "run", .lease_id = lease_id};
      return Deny(c, "no such lease", "execute");
    }
    Conversation &c = it->second;
    if (Expired(c)) {
      Conversation copy = c;
      lease_conversations_.erase(c.lease_id);
      conversations_.erase(it);
      return Deny(copy, "conversation expired", "execute",
                  copy.command_summary);
    }
    if (!c.approved || c.kind != "run")
      return Deny(c, "lease is not approved for execute", "execute",
                  c.command_summary);
    std::string service_error;
    const Service *s = FindServiceFresh(c.service, &service_error);
    if (!s)
      return Error(service_error);
    std::uint32_t left = 0;
    std::string lease_service;
    auto lease_status =
        leases_.Consume(lease_id, c.service, &left, &lease_service);
    if (lease_status != LeaseTable::Status::kOk)
      return Deny(c, LeaseReason(lease_status), "execute", c.command_summary);
    c.lease_uses_remaining = left;
    auto st = Audit(AuditEntry{.conversation_id = c.id,
                               .event = "execute_start",
                               .agent = c.agent,
                               .service = c.service,
                               .intent = c.intent,
                               .details = c.details,
                               .command_summary = c.command_summary,
                               .transcript = Transcript(c),
                               .verdict = "granted",
                               .rationale = c.rationale,
                               .ttl_seconds = c.ttl_seconds,
                               .max_uses = c.max_uses,
                               .disclosure = DisclosureName(s->disclosure)});
    if (!st.ok())
      return AuditError(st);
    return DeliverCredential(c, *s);
  }

  std::string ExecuteResult(const json &req) {
    std::string id = req.value("conversation_id", "");
    auto it = conversations_.find(id);
    if (it == conversations_.end())
      return json{{"status", "ok"}}.dump();
    Conversation c = it->second;
    if (c.lease_uses_remaining == 0) {
      lease_conversations_.erase(c.lease_id);
      conversations_.erase(it);
    }
    const Service *s = vault_.Find(c.service);
    auto st =
        Audit(AuditEntry{.conversation_id = c.id,
                         .event = "execute_result",
                         .agent = c.agent,
                         .service = c.service,
                         .intent = c.intent,
                         .details = c.details,
                         .command_summary = c.command_summary,
                         .transcript = Transcript(c),
                         .verdict = "granted",
                         .rationale = c.rationale,
                         .ttl_seconds = c.ttl_seconds,
                         .max_uses = c.max_uses,
                         .disclosure = s ? DisclosureName(s->disclosure) : "",
                         .child_exit_code = req.value("child_exit_code", -1),
                         .redacted = req.value("redacted", false)});
    if (!st.ok())
      return AuditError(st);
    return json{{"status", "ok"}}.dump();
  }

  std::string ExposeFinal(const json &req) {
    std::string lease_id = req.value("lease_id", "");
    auto lease_it = lease_conversations_.find(lease_id);
    if (lease_it == lease_conversations_.end()) {
      Conversation c{.id = lease_id, .kind = "expose", .lease_id = lease_id};
      return Deny(c, "no such lease", "expose_final");
    }
    std::string id = lease_it->second;
    auto it = conversations_.find(id);
    if (it == conversations_.end()) {
      lease_conversations_.erase(lease_it);
      Conversation c{.id = lease_id, .kind = "expose", .lease_id = lease_id};
      return Deny(c, "no such lease", "expose_final");
    }
    Conversation &c = it->second;
    if (Expired(c)) {
      Conversation copy = c;
      lease_conversations_.erase(c.lease_id);
      conversations_.erase(it);
      return Deny(copy, "conversation expired", "expose_final");
    }
    if (!c.approved || c.kind != "expose")
      return Deny(c, "lease is not approved for expose", "expose_final");
    std::uint32_t left = 0;
    std::string lease_service;
    auto lease_status =
        leases_.Consume(lease_id, c.service, &left, &lease_service);
    if (lease_status != LeaseTable::Status::kOk) {
      Conversation denied = c;
      lease_conversations_.erase(c.lease_id);
      conversations_.erase(it);
      return Deny(denied, LeaseReason(lease_status), "expose_final");
    }
    c.lease_uses_remaining = left;
    Conversation delivered = c;
    if (left == 0) {
      lease_conversations_.erase(c.lease_id);
      conversations_.erase(it);
    }
    std::string service_error;
    const Service *s = FindServiceFresh(delivered.service, &service_error);
    if (!s)
      return Error(service_error);
    if (s->disclosure != Disclosure::kReveal)
      return Deny(delivered, "service does not permit revealing its value",
                  "expose_final");
    auto st = Audit(AuditEntry{.conversation_id = delivered.id,
                               .event = "expose_final",
                               .agent = delivered.agent,
                               .service = delivered.service,
                               .intent = delivered.intent,
                               .details = delivered.details,
                               .transcript = Transcript(delivered),
                               .verdict = "granted",
                               .rationale = delivered.rationale,
                               .ttl_seconds = delivered.ttl_seconds,
                               .max_uses = delivered.max_uses,
                               .disclosure = DisclosureName(s->disclosure)});
    if (!st.ok())
      return AuditError(st);
    return DeliverCredential(delivered, *s);
  }

  Vault vault_;
  std::unique_ptr<Arbiter> arbiter_;
  AuditLog audit_;
  LeaseTable leases_;
  std::map<std::string, Conversation> conversations_;
  std::map<std::string, std::string> lease_conversations_;
};

} // namespace

int CmdServe(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  std::string dir = a.Get("vault", VaultDir());
  std::string model = a.Get("model"); // empty => heuristic backend
  std::string backend = a.Get("backend", "cpu");

  std::string pass = ReadPassphrase("Vault passphrase: ");
  auto vault = Vault::Open(dir, pass);
  if (!vault.ok()) {
    std::fprintf(stderr, "prout: cannot open vault: %s\n",
                 std::string(vault.status().message()).c_str());
    return kExitError;
  }

  std::fprintf(stderr, "prout: loading arbiter%s...\n",
               model.empty() ? " (heuristic, no model)" : "");
  auto arbiter = Arbiter::Create(model, backend);
  if (!arbiter.ok()) {
    std::fprintf(stderr, "prout: %s\n",
                 std::string(arbiter.status().message()).c_str());
    return kExitError;
  }

  Daemon daemon(std::move(*vault), std::move(*arbiter), dir);

  IpcServer server;
  auto st = server.Listen(SocketPath());
  if (!st.ok()) {
    std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
    return kExitError;
  }
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);
  std::fprintf(stderr, "prout: serving on %s (Ctrl-C to stop)\n",
               SocketPath().c_str());

  auto serve_status =
      server.Serve([&](const std::string &req) { return daemon.Handle(req); },
                   [] { return g_stop.load(); });
  server.Close();
  if (!serve_status.ok()) {
    std::fprintf(stderr, "prout: %s\n",
                 std::string(serve_status.message()).c_str());
    return kExitError;
  }
  std::fprintf(stderr, "prout: stopped\n");
  return kExitOk;
}

} // namespace prout

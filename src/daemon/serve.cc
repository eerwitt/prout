// The long-lived daemon: loads the vault + keeps Gemma warm, then serves
// negotiation requests over the AF_UNIX socket. Single-threaded and serialized
// -- one model, one user -- which keeps lease state trivially consistent.
#include <atomic>
#include <csignal>
#include <cstdio>
#include <memory>
#include <string>

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
#include "vault/vault.h"

namespace prout {
using json = nlohmann::json;

namespace {

std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

struct Pending {
  std::string service;
  std::string op; // "run" or "get"
  std::string agent;
  std::string intent;
};

class Daemon {
public:
  Daemon(Vault vault, std::unique_ptr<Arbiter> arbiter, std::string dir)
      : vault_(std::move(vault)), arbiter_(std::move(arbiter)),
        audit_(std::move(dir)) {}

  std::string Handle(const std::string &request) {
    json req = json::parse(request, nullptr, false);
    if (req.is_discarded())
      return Error("malformed request");
    std::string op = req.value("op", "");
    if (op == "ping") {
      return json{{"status", "ok"}, {"model", arbiter_->using_model()}}.dump();
    }
    if (op == "run" || op == "get")
      return Negotiate(op, req);
    if (op == "answer")
      return Answer(req);
    if (op == "reuse")
      return Reuse(req);
    return Error("unknown op '" + op + "'");
  }

private:
  static std::string Error(const std::string &m) {
    return json{{"status", "error"}, {"message", m}}.dump();
  }

  // Builds a granted response, creating a lease and consuming its first use.
  std::string Grant(const Service &s, const std::string &op, std::uint32_t ttl,
                    std::uint32_t uses, const std::string &rationale) {
    if (ttl == 0 || uses == 0)
      return Deny(s.name, "invalid zero lease ceiling");
    auto lease_id_or = leases_.Create(s.name, ttl, uses);
    if (!lease_id_or.ok())
      return Error("could not create lease: " +
                   std::string(lease_id_or.status().message()));
    std::string lease_id = *lease_id_or;
    std::uint32_t left = 0;
    leases_.Consume(lease_id, s.name, &left); // this delivery counts as a use

    auto audit_status =
        audit_.Append(AuditEntry{.agent = last_agent_,
                                 .service = s.name,
                                 .intent = last_intent_,
                                 .transcript = last_transcript_,
                                 .verdict = "granted",
                                 .rationale = rationale,
                                 .ttl_seconds = ttl,
                                 .max_uses = uses,
                                 .disclosure = DisclosureName(s.disclosure)});
    if (!audit_status.ok())
      return Error("could not append audit record: " +
                   std::string(audit_status.message()));

    std::string credential(reinterpret_cast<const char *>(s.credential.data()),
                           s.credential.size());
    json r{
        {"status", "granted"},     {"lease_id", lease_id},
        {"ttl_seconds", ttl},      {"max_uses", uses},
        {"uses_remaining", left},  {"rationale", rationale},
        {"env_var", s.env_var},    {"disclosure", DisclosureName(s.disclosure)},
        {"credential", credential}};
    std::string out = r.dump();
    SecureZero(credential.data(), credential.size());
    return out;
  }

  std::string Deny(const std::string &service, const std::string &rationale) {
    auto audit_status = audit_.Append(AuditEntry{.agent = last_agent_,
                                                 .service = service,
                                                 .intent = last_intent_,
                                                 .transcript = last_transcript_,
                                                 .verdict = "denied",
                                                 .rationale = rationale});
    if (!audit_status.ok())
      return Error("could not append audit record: " +
                   std::string(audit_status.message()));
    return json{{"status", "denied"}, {"rationale", rationale}}.dump();
  }

  std::string AskQuestion(const std::string &service, const std::string &nid,
                          const std::string &text) {
    auto audit_status =
        audit_.Append(AuditEntry{.agent = last_agent_,
                                 .service = service,
                                 .intent = last_intent_,
                                 .transcript = "question: " + text,
                                 .verdict = "question",
                                 .rationale = text});
    if (!audit_status.ok())
      return Error("could not append audit record: " +
                   std::string(audit_status.message()));
    return json{{"status", "question"}, {"negotiation_id", nid}, {"text", text}}
        .dump();
  }

  std::string Deliver(const Service &s, const std::string &op,
                      const Verdict &v) {
    if (s.policy.max_ttl_seconds == 0 || s.policy.max_uses == 0)
      return Deny(s.name, "service policy has zero lease ceiling");
    if (op == "get" && s.disclosure != Disclosure::kReveal)
      return Deny(s.name,
                  "service '" + s.name +
                      "' does not permit revealing its value; use `prout run`");
    return Grant(s, op, v.ttl_seconds, v.max_uses, v.rationale);
  }

  std::string Negotiate(const std::string &op, const json &req) {
    std::string service = req.value("service", "");
    last_agent_ = req.value("agent", "agent");
    last_intent_ = req.value("intent", "");
    last_transcript_ = "intent: " + last_intent_;

    const Service *s = vault_.Find(service);
    if (!s)
      return Error("unknown service '" + service + "'");
    if (last_intent_.empty())
      return Error("missing intent");

    std::string nid;
    Verdict v = arbiter_->Begin(*s, last_agent_, last_intent_, &nid);
    if (v.type == Verdict::Type::kQuestion) {
      pending_[nid] = Pending{service, op, last_agent_, last_intent_};
      return AskQuestion(service, nid, v.question);
    }
    if (v.type == Verdict::Type::kDeny)
      return Deny(service, v.rationale);
    return Deliver(*s, op, v);
  }

  std::string Answer(const json &req) {
    std::string nid = req.value("negotiation_id", "");
    std::string answer = req.value("answer", "");
    auto it = pending_.find(nid);
    if (it == pending_.end())
      return Error("unknown or expired negotiation id '" + nid + "'");
    Pending ctx = it->second;
    last_agent_ = ctx.agent;
    last_intent_ = ctx.intent;
    last_transcript_ = "intent: " + ctx.intent + " | answer: " + answer;

    const Service *s = vault_.Find(ctx.service);
    if (!s) {
      pending_.erase(it);
      return Error("service vanished from vault");
    }
    Verdict v = arbiter_->Reply(nid, answer);
    if (v.type == Verdict::Type::kQuestion) {
      // Same negotiation id continues.
      return AskQuestion(ctx.service, nid, v.question);
    }
    pending_.erase(nid);
    if (v.type == Verdict::Type::kDeny)
      return Deny(ctx.service, v.rationale);
    return Deliver(*s, ctx.op, v);
  }

  std::string Reuse(const json &req) {
    std::string lease_id = req.value("lease_id", "");
    last_agent_ = req.value("agent", "agent");
    std::uint32_t left = 0;
    std::string service;
    auto st = leases_.Consume(lease_id, /*expect_service=*/"", &left, &service);
    const char *reason = nullptr;
    switch (st) {
    case LeaseTable::Status::kUnknown:
      reason = "no such lease";
      break;
    case LeaseTable::Status::kExpired:
      reason = "lease expired";
      break;
    case LeaseTable::Status::kExhausted:
      reason = "lease fully used";
      break;
    case LeaseTable::Status::kWrongService:
      reason = "lease is for a different service";
      break;
    case LeaseTable::Status::kOk:
      break;
    }
    if (reason) {
      last_intent_ = "(lease reuse)";
      last_transcript_ = "reuse lease " + lease_id;
      return Deny(service, reason);
    }
    const Service *s = vault_.Find(service);
    if (!s)
      return Error("unknown service for lease");
    std::string credential(reinterpret_cast<const char *>(s->credential.data()),
                           s->credential.size());
    auto audit_status =
        audit_.Append(AuditEntry{.agent = last_agent_,
                                 .service = service,
                                 .intent = "(lease reuse)",
                                 .transcript = "reuse lease " + lease_id,
                                 .verdict = "granted",
                                 .rationale = "reused existing lease",
                                 .disclosure = DisclosureName(s->disclosure)});
    if (!audit_status.ok()) {
      SecureZero(credential.data(), credential.size());
      return Error("could not append audit record: " +
                   std::string(audit_status.message()));
    }
    json r{{"status", "granted"},
           {"lease_id", lease_id},
           {"uses_remaining", left},
           {"rationale", "reused existing lease"},
           {"env_var", s->env_var},
           {"disclosure", DisclosureName(s->disclosure)},
           {"credential", credential}};
    std::string out = r.dump();
    SecureZero(credential.data(), credential.size());
    return out;
  }

  Vault vault_;
  std::unique_ptr<Arbiter> arbiter_;
  AuditLog audit_;
  LeaseTable leases_;
  std::map<std::string, Pending> pending_;
  std::string last_agent_, last_intent_, last_transcript_;
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

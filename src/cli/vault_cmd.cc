#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "arbiter/arbiter.h"
#include "audit/audit.h"
#include "cli/args.h"
#include "cli/commands.h"
#include "common/paths.h"
#include "common/prompt.h"
#include "common/secure_mem.h"
#include "vault/crypto.h"
#include "vault/vault.h"

namespace prout {
namespace {

void VaultUsage() {
  std::fprintf(
      stderr,
      "usage:\n"
      "  prout vault init [--vault <dir>]\n"
      "  prout vault add <service> --inject-env <VAR> --website <url> "
      "--company <name> --details <text> [--disclosure inject|reveal] "
      "[--max-ttl <sec>] [--max-uses <n>] [--description <text>] "
      "[--guidance <text>] [--expires-at <utc>] [--generate]\n"
      "  prout vault edit <service> [same metadata/policy flags] "
      "[--credential] [--generate]\n"
      "  prout vault delete <service>\n"
      "  prout vault list [--vault <dir>]\n"
      "  prout vault generate [--length <n>] [--lower] [--upper] [--digits] "
      "[--symbols] [--no-ambiguous]\n");
}

std::uint32_t ParseU32(const std::string &s, std::uint32_t def) {
  if (s.empty())
    return def;
  char *end = nullptr;
  unsigned long v = std::strtoul(s.c_str(), &end, 10);
  if (end == s.c_str() || *end != '\0')
    return def;
  return static_cast<std::uint32_t>(v);
}

absl::StatusOr<Vault> OpenVault(const Args &a) {
  return Vault::Open(a.Get("vault", VaultDir()),
                     ReadPassphrase("Vault passphrase: "));
}

std::string Lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

std::string NormalizeHost(std::string url) {
  auto scheme = url.find("://");
  if (scheme != std::string::npos)
    url.erase(0, scheme + 3);
  auto at = url.find('@');
  if (at != std::string::npos)
    url.erase(0, at + 1);
  auto slash = url.find_first_of("/?#");
  if (slash != std::string::npos)
    url.erase(slash);
  if (!url.empty() && url.front() == '[') {
    auto close = url.find(']');
    if (close != std::string::npos)
      return Lower(url.substr(1, close - 1));
  }
  auto colon = url.find(':');
  if (colon != std::string::npos)
    url.erase(colon);
  while (!url.empty() && url.back() == '.')
    url.pop_back();
  return Lower(url);
}

Service FromFlags(const Args &a, const std::string &name) {
  Service s;
  s.name = name;
  s.inject_env = a.Get("inject-env", a.Get("env"));
  s.disclosure = *ParseDisclosure(a.Get("disclosure", "inject"));
  s.policy.max_ttl_seconds =
      ParseU32(a.Get("max-ttl"), s.policy.max_ttl_seconds);
  s.policy.max_uses = ParseU32(a.Get("max-uses"), s.policy.max_uses);
  s.policy.description = a.Get("description");
  s.policy.guidance = a.Get("guidance");
  s.website_url = a.Get("website");
  s.website_host = NormalizeHost(s.website_url);
  s.company = a.Get("company");
  s.details = a.Get("details");
  s.expires_at = a.Get("expires-at");
  return s;
}

Service EditableCopy(const Service &s) {
  Service out;
  out.name = s.name;
  out.inject_env = s.inject_env;
  out.disclosure = s.disclosure;
  out.policy = s.policy;
  out.website_url = s.website_url;
  out.website_host = s.website_host;
  out.company = s.company;
  out.details = s.details;
  out.expires_at = s.expires_at;
  out.created_at = s.created_at;
  out.updated_at = s.updated_at;
  out.update_timestamps = s.update_timestamps;
  return out;
}

void ApplyEditFlags(const Args &a, Service *s) {
  if (a.Has("inject-env"))
    s->inject_env = a.Get("inject-env");
  if (a.Has("env"))
    s->inject_env = a.Get("env");
  if (a.Has("disclosure"))
    s->disclosure = *ParseDisclosure(a.Get("disclosure"));
  if (a.Has("max-ttl"))
    s->policy.max_ttl_seconds =
        ParseU32(a.Get("max-ttl"), s->policy.max_ttl_seconds);
  if (a.Has("max-uses"))
    s->policy.max_uses = ParseU32(a.Get("max-uses"), s->policy.max_uses);
  if (a.Has("description"))
    s->policy.description = a.Get("description");
  if (a.Has("guidance"))
    s->policy.guidance = a.Get("guidance");
  if (a.Has("website")) {
    s->website_url = a.Get("website");
    s->website_host = NormalizeHost(s->website_url);
  }
  if (a.Has("company"))
    s->company = a.Get("company");
  if (a.Has("details"))
    s->details = a.Get("details");
  if (a.Has("expires-at"))
    s->expires_at = a.Get("expires-at");
}

std::string NewVaultEventId() {
  std::uint8_t bytes[16]{};
  if (!RandomBytes(bytes, sizeof(bytes)).ok())
    return "vault-random-failed";
  return "vault-" + ToHex(bytes, sizeof(bytes));
}

std::string MetadataSummary(const Service &s) {
  return "inject_env=" + s.inject_env +
         " disclosure=" + DisclosureName(s.disclosure) +
         " website_host=" + s.website_host + " company=" + s.company;
}

std::string Advice(const Args &a, const std::string &action, const Service *s) {
  if (!a.Has("model") || a.Get("model").empty() || !s)
    return "local schema and safety checks accepted " + action;

  auto arbiter = Arbiter::Create(a.Get("model"), a.Get("backend", "cpu"));
  if (!arbiter.ok())
    return "model advisory unavailable: " +
           std::string(arbiter.status().message()) +
           "; local schema and safety checks accepted " + action;

  std::string intent = action + " vault service with " + MetadataSummary(*s) +
                       " details=" + s->details;
  std::string negotiation_id;
  Verdict v = (*arbiter)->Begin(*s, "vault-cli", intent, "", &negotiation_id);
  if (v.type == Verdict::Type::kQuestion)
    return "model asked: " + v.question +
           "; local schema and safety checks accepted " + action;
  if (v.type == Verdict::Type::kDeny)
    return "model advised deny: " + v.rationale +
           "; advisory only, local schema and safety checks accepted " + action;
  return "model advised accept: " + v.rationale;
}

void AuditVaultMutation(const std::string &dir, const std::string &action,
                        const std::string &service, const std::string &summary,
                        const std::string &advice) {
  AuditLog log(dir);
  (void)log.Append(AuditEntry{.conversation_id = NewVaultEventId(),
                              .event = "vault_" + action,
                              .agent = "vault-cli",
                              .service = service,
                              .intent = action + " vault service",
                              .details = summary,
                              .transcript = summary,
                              .verdict = "granted",
                              .rationale = advice});
}

std::string GeneratePassword(const Args &a) {
  const std::string lower = "abcdefghjkmnpqrstuvwxyz";
  const std::string upper = "ABCDEFGHJKMNPQRSTUVWXYZ";
  const std::string digits = "23456789";
  const std::string symbols = "!@#$%^&*()-_=+[]{};:,.?";
  bool explicit_set =
      a.Has("lower") || a.Has("upper") || a.Has("digits") || a.Has("symbols");
  std::string alphabet;
  if (!explicit_set || a.Has("lower"))
    alphabet += lower;
  if (!explicit_set || a.Has("upper"))
    alphabet += upper;
  if (!explicit_set || a.Has("digits"))
    alphabet += digits;
  if (!explicit_set || a.Has("symbols"))
    alphabet += symbols;
  if (alphabet.empty())
    alphabet = lower + upper + digits + symbols;
  std::uint32_t length = ParseU32(a.Get("length"), 32);
  if (length < 8)
    length = 8;
  std::vector<std::uint8_t> bytes(length);
  if (!RandomBytes(bytes.data(), bytes.size()).ok())
    return std::string();
  std::string out;
  out.reserve(length);
  for (std::uint8_t b : bytes)
    out.push_back(alphabet[b % alphabet.size()]);
  SecureZero(bytes.data(), bytes.size());
  return out;
}

void ShowGeneratedUntilEnter(const std::string &password) {
  std::fwrite(password.data(), 1, password.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
  std::string ignored;
  std::getline(std::cin, ignored);
  ClearSensitiveTerminalArea();
}

absl::StatusOr<SecureBuffer> CaptureCredential(const Args &a) {
  std::string cred;
  if (a.Has("generate")) {
    cred = GeneratePassword(a);
    if (cred.empty())
      return absl::InternalError("password generation failed");
    ShowGeneratedUntilEnter(cred);
  } else if (const char *env_cred = std::getenv("PROUT_CREDENTIAL")) {
    cred = std::string(env_cred);
  } else {
    cred = ReadSecretLine("Credential value: ");
  }
  if (cred.empty())
    return absl::InvalidArgumentError("empty credential refused");
  SecureBuffer c;
  c.assign(cred);
  SecureZero(cred.data(), cred.size());
  return c;
}

} // namespace

int CmdVault(const std::vector<std::string> &argv) {
  if (argv.empty()) {
    VaultUsage();
    return kExitError;
  }
  std::string sub = argv[0];
  std::vector<std::string> rest(argv.begin() + 1, argv.end());
  Args a = ParseArgs(rest);
  std::string dir = a.Get("vault", VaultDir());

  if (sub == "init") {
    std::string pass = ReadPassphrase("New vault passphrase: ");
    auto st = Vault::Init(dir, pass);
    SecureZero(pass.data(), pass.size());
    if (!st.ok()) {
      std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
      return kExitError;
    }
    std::fprintf(stdout, "initialized vault at %s\n", dir.c_str());
    return kExitOk;
  }

  if (sub == "generate") {
    std::string password = GeneratePassword(a);
    if (password.empty()) {
      std::fprintf(stderr, "prout: password generation failed\n");
      return kExitError;
    }
    ShowGeneratedUntilEnter(password);
    SecureZero(password.data(), password.size());
    return kExitOk;
  }

  if (sub == "add") {
    if (a.positional.empty() || a.Get("inject-env", a.Get("env")).empty()) {
      VaultUsage();
      return kExitError;
    }
    auto disclosure = ParseDisclosure(a.Get("disclosure", "inject"));
    if (!disclosure.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(disclosure.status().message()).c_str());
      return kExitError;
    }
    Service s = FromFlags(a, a.positional[0]);
    s.disclosure = *disclosure;
    auto cred = CaptureCredential(a);
    if (!cred.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(cred.status().message()).c_str());
      return kExitError;
    }
    auto vault = OpenVault(a);
    if (!vault.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(vault.status().message()).c_str());
      return kExitError;
    }
    std::string advice = Advice(a, "add", &s);
    std::string added_name = s.name;
    std::string added_disclosure = DisclosureName(s.disclosure);
    std::string added_summary = MetadataSummary(s);
    auto st = vault->AddService(std::move(s), std::move(*cred));
    if (!st.ok()) {
      std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
      return kExitError;
    }
    AuditVaultMutation(dir, "add", added_name, added_summary, advice);
    std::fprintf(stdout, "added service %s (%s)\n", added_name.c_str(),
                 added_disclosure.c_str());
    return kExitOk;
  }

  if (sub == "edit") {
    if (a.positional.empty()) {
      VaultUsage();
      return kExitError;
    }
    auto vault = OpenVault(a);
    if (!vault.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(vault.status().message()).c_str());
      return kExitError;
    }
    const Service *existing = vault->Find(a.positional[0]);
    if (!existing) {
      std::fprintf(stderr, "prout: unknown service '%s'\n",
                   a.positional[0].c_str());
      return kExitError;
    }
    if (a.Has("disclosure") && !ParseDisclosure(a.Get("disclosure")).ok()) {
      std::fprintf(stderr, "prout: disclosure must be 'inject' or 'reveal'\n");
      return kExitError;
    }
    Service edited = EditableCopy(*existing);
    ApplyEditFlags(a, &edited);
    SecureBuffer new_cred;
    SecureBuffer *cred_ptr = nullptr;
    if (a.Has("credential") || a.Has("generate")) {
      auto cred = CaptureCredential(a);
      if (!cred.ok()) {
        std::fprintf(stderr, "prout: %s\n",
                     std::string(cred.status().message()).c_str());
        return kExitError;
      }
      new_cred = std::move(*cred);
      cred_ptr = &new_cred;
    }
    std::string advice = Advice(a, "edit", &edited);
    auto st = vault->EditService(edited.name, edited, cred_ptr);
    if (!st.ok()) {
      std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
      return kExitError;
    }
    AuditVaultMutation(dir, "edit", edited.name, MetadataSummary(edited),
                       advice);
    std::fprintf(stdout, "edited service %s\n", edited.name.c_str());
    return kExitOk;
  }

  if (sub == "delete") {
    if (a.positional.empty()) {
      VaultUsage();
      return kExitError;
    }
    auto vault = OpenVault(a);
    if (!vault.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(vault.status().message()).c_str());
      return kExitError;
    }
    const Service *existing = vault->Find(a.positional[0]);
    std::string summary =
        existing ? MetadataSummary(*existing) : "unknown service";
    std::string advice = Advice(a, "delete", existing);
    auto st = vault->DeleteService(a.positional[0]);
    if (!st.ok()) {
      std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
      return kExitError;
    }
    AuditVaultMutation(dir, "delete", a.positional[0], summary, advice);
    std::fprintf(stdout, "deleted service %s\n", a.positional[0].c_str());
    return kExitOk;
  }

  if (sub == "list") {
    auto vault = OpenVault(a);
    if (!vault.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(vault.status().message()).c_str());
      return kExitError;
    }
    for (const auto &name : vault->ServiceNames()) {
      const Service *s = vault->Find(name);
      std::fprintf(
          stdout, "%s\t%s\t%s\t%s\t%s\tmax_ttl=%u\tmax_uses=%u\tupdated=%s\n",
          s->name.c_str(), s->inject_env.c_str(),
          DisclosureName(s->disclosure).c_str(), s->website_host.c_str(),
          s->company.c_str(), s->policy.max_ttl_seconds, s->policy.max_uses,
          s->updated_at.c_str());
    }
    return kExitOk;
  }

  VaultUsage();
  return kExitError;
}

} // namespace prout

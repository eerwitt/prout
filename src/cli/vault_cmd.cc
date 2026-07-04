#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "cli/args.h"
#include "cli/commands.h"
#include "common/paths.h"
#include "common/prompt.h"
#include "common/secure_mem.h"
#include "vault/vault.h"

namespace prout {
namespace {

void VaultUsage() {
  std::fprintf(
      stderr,
      "usage:\n"
      "  prout vault init [--vault <dir>]\n"
      "  prout vault add <service> --env <VAR> [--disclosure inject|reveal] "
      "[--max-ttl <sec>] [--max-uses <n>] [--description <text>] "
      "[--guidance <text>]\n"
      "  prout vault list [--vault <dir>]\n");
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

  if (sub == "add") {
    if (a.positional.empty() || a.Get("env").empty()) {
      VaultUsage();
      return kExitError;
    }
    auto vault = OpenVault(a);
    if (!vault.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(vault.status().message()).c_str());
      return kExitError;
    }
    auto disclosure = ParseDisclosure(a.Get("disclosure", "inject"));
    if (!disclosure.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(disclosure.status().message()).c_str());
      return kExitError;
    }
    Policy p;
    p.max_ttl_seconds = ParseU32(a.Get("max-ttl"), p.max_ttl_seconds);
    p.max_uses = ParseU32(a.Get("max-uses"), p.max_uses);
    p.description = a.Get("description");
    p.guidance = a.Get("guidance");
    if (p.max_ttl_seconds == 0 || p.max_uses == 0) {
      std::fprintf(stderr, "prout: policy ceilings must be non-zero\n");
      return kExitError;
    }

    const char *env_cred = std::getenv("PROUT_CREDENTIAL");
    std::string cred = env_cred ? std::string(env_cred) : std::string();
    if (cred.empty()) {
      std::fprintf(stderr, "Credential value: ");
      std::fflush(stderr);
      std::getline(std::cin, cred);
    }
    if (cred.empty()) {
      std::fprintf(stderr, "prout: empty credential refused\n");
      return kExitError;
    }
    SecureBuffer c;
    c.assign(cred);
    SecureZero(cred.data(), cred.size());
    auto st = vault->AddService(a.positional[0], a.Get("env"), *disclosure, p,
                                std::move(c));
    if (!st.ok()) {
      std::fprintf(stderr, "prout: %s\n", std::string(st.message()).c_str());
      return kExitError;
    }
    std::fprintf(stdout, "added service %s (%s)\n", a.positional[0].c_str(),
                 DisclosureName(*disclosure).c_str());
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
      std::fprintf(stdout, "%s\t%s\t%s\tmax_ttl=%u\tmax_uses=%u\n",
                   s->name.c_str(), s->env_var.c_str(),
                   DisclosureName(s->disclosure).c_str(),
                   s->policy.max_ttl_seconds, s->policy.max_uses);
    }
    return kExitOk;
  }

  VaultUsage();
  return kExitError;
}

} // namespace prout

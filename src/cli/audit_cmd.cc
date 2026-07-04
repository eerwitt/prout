#include <cstdio>
#include <string>
#include <vector>

#include "audit/audit.h"
#include "cli/args.h"
#include "cli/commands.h"
#include "common/paths.h"

namespace prout {
namespace {

void AuditUsage() {
  std::fprintf(stderr, "usage:\n"
                       "  prout audit tail [--vault <dir>] [--n <count>]\n"
                       "  prout audit verify [--vault <dir>]\n"
                       "  prout audit conversation <id> [--vault <dir>]\n");
}

int ParseInt(const std::string &s, int def) {
  if (s.empty())
    return def;
  try {
    return std::stoi(s);
  } catch (...) {
    return def;
  }
}

} // namespace

int CmdAudit(const std::vector<std::string> &argv) {
  if (argv.empty()) {
    AuditUsage();
    return kExitError;
  }
  std::string sub = argv[0];
  std::vector<std::string> rest(argv.begin() + 1, argv.end());
  Args a = ParseArgs(rest);
  AuditLog log(a.Get("vault", VaultDir()));

  if (sub == "tail") {
    auto lines = log.Tail(ParseInt(a.Get("n"), 20));
    if (!lines.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(lines.status().message()).c_str());
      return kExitError;
    }
    for (const auto &line : *lines)
      std::fprintf(stdout, "%s\n", line.c_str());
    return kExitOk;
  }

  if (sub == "conversation") {
    if (a.positional.empty()) {
      AuditUsage();
      return kExitError;
    }
    auto lines = log.Conversation(a.positional[0]);
    if (!lines.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(lines.status().message()).c_str());
      return kExitError;
    }
    for (const auto &line : *lines)
      std::fprintf(stdout, "%s\n", line.c_str());
    return kExitOk;
  }

  if (sub == "verify") {
    auto st = log.Verify();
    if (!st.ok()) {
      std::fprintf(stderr, "prout: audit verification failed: %s\n",
                   std::string(st.message()).c_str());
      return kExitError;
    }
    std::fprintf(stdout, "audit ok\n");
    return kExitOk;
  }

  AuditUsage();
  return kExitError;
}

} // namespace prout

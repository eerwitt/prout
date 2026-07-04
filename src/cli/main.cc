#include <cstdio>
#include <string>
#include <vector>

#include "cli/commands.h"

namespace {

void Usage() {
  std::fprintf(
      stderr,
      "usage: prout <command> [args]\n\n"
      "commands:\n"
      "  serve [--model <path>] [--backend cpu|gpu] [--vault <dir>]\n"
      "  vault init|add|list ...\n"
      "  run --service <name> --intent <text> [--agent <name>] -- <cmd...>\n"
      "  run --conversation <id> --details <text> [--agent <name>]\n"
      "  expose --service <name> --intent <text> [--agent <name>]\n"
      "  expose --conversation <id> [--details <text>] [--agent <name>]\n"
      "  expose --lease <id>\n"
      "  execute --lease <id>\n"
      "  audit tail|verify|conversation [--vault <dir>]\n\n"
      "inject flow:\n"
      "  prout run --service <name> --intent \"<why>\" [--agent <name>] -- "
      "<cmd...>\n"
      "  prout execute --lease <approved-lease-id>\n"
      "  # if run returns status=question, answer with:\n"
      "  prout run --conversation <id> --details \"<answer>\" [--agent "
      "<name>]\n\n"
      "reveal flow:\n"
      "  prout expose --service <name> --intent \"<why>\" [--agent <name>]\n"
      "  prout expose --lease <approved-lease-id>\n");
}

std::vector<std::string> TailArgs(int argc, char **argv) {
  std::vector<std::string> out;
  out.reserve(argc > 2 ? static_cast<std::size_t>(argc - 2) : 0);
  for (int i = 2; i < argc; ++i)
    out.emplace_back(argv[i]);
  return out;
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    Usage();
    return prout::kExitError;
  }
  std::string cmd = argv[1];
  std::vector<std::string> args = TailArgs(argc, argv);
  if (cmd == "serve")
    return prout::CmdServe(args);
  if (cmd == "vault")
    return prout::CmdVault(args);
  if (cmd == "run")
    return prout::CmdRun(args);
  if (cmd == "expose")
    return prout::CmdExpose(args);
  if (cmd == "execute")
    return prout::CmdExecute(args);
  if (cmd == "audit")
    return prout::CmdAudit(args);
  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    Usage();
    return prout::kExitOk;
  }
  std::fprintf(stderr, "prout: unknown command '%s'\n", cmd.c_str());
  Usage();
  return prout::kExitError;
}

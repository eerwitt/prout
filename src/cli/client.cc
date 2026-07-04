// Client-side subcommands. These are thin: build a request, send it to the
// daemon over the socket, and act on the single JSON reply. The credential,
// when granted, is received here (the trusted client) and either injected into
// a child process's environment or printed for `get` -- it is never shown to
// the calling agent's own output stream for `run`.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "cli/args.h"
#include "cli/commands.h"
#include "common/paths.h"
#include "common/secure_mem.h"
#include "ipc/ipc.h"
#include "nlohmann/json.hpp"

#if defined(_WIN32)
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace prout {
using json = nlohmann::json;

namespace {

void SetEnv(const std::string &name, const char *value) {
#if defined(_WIN32)
  _putenv_s(name.c_str(), value);
#else
  setenv(name.c_str(), value, 1);
#endif
}
void UnsetEnv(const std::string &name) {
#if defined(_WIN32)
  _putenv_s(name.c_str(), "");
#else
  unsetenv(name.c_str());
#endif
}

// Runs `command` (argv) inheriting the current environment. Returns its exit
// code, or 127 if it could not be launched.
int SpawnChild(const std::vector<std::string> &command) {
  if (command.empty())
    return 127;
  std::vector<char *> argv;
  for (const auto &a : command)
    argv.push_back(const_cast<char *>(a.c_str()));
  argv.push_back(nullptr);
#if defined(_WIN32)
  intptr_t rc = _spawnvp(_P_WAIT, argv[0], argv.data());
  if (rc == -1) {
    std::fprintf(stderr, "prout: failed to run '%s'\n", argv[0]);
    return 127;
  }
  return static_cast<int>(rc);
#else
  pid_t pid = fork();
  if (pid < 0)
    return 127;
  if (pid == 0) {
    execvp(argv[0], argv.data());
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
#endif
}

absl::StatusOr<json> Send(const json &request) {
  auto resp = IpcRequest(SocketPath(), request.dump());
  if (!resp.ok())
    return resp.status();
  json j = json::parse(*resp, nullptr, false);
  if (j.is_discarded())
    return absl::InternalError("bad response from daemon");
  return j;
}

// Delivers a granted credential either by injecting it into a child's env and
// running the child (inject mode), or by printing it to stdout (reveal mode).
int UseGranted(const json &r, const std::vector<std::string> &command) {
  std::string env_var = r.value("env_var", "");
  // Copy credential into locked memory, then wipe the JSON's copy.
  SecureBuffer cred;
  {
    std::string c = r.value("credential", "");
    cred.assign(c);
    SecureZero(c.data(), c.size());
  }

  // Status line (no credential) so the agent can see what was granted.
  std::fprintf(stderr, "prout: granted lease %s  ttl=%us  uses_left=%u  (%s)\n",
               r.value("lease_id", "?").c_str(), r.value("ttl_seconds", 0u),
               r.value("uses_remaining", 0u), r.value("rationale", "").c_str());

  if (!command.empty()) {
    SetEnv(env_var, cred.c_str());
    int code = SpawnChild(command);
    UnsetEnv(env_var);
    cred.clear();
    return code;
  }
  if (r.value("disclosure", "inject") != "reveal") {
    std::fprintf(stderr, "prout: granted credential is inject-only; no child "
                         "command was provided\n");
    cred.clear();
    return kExitError;
  }
  // Reveal mode: emit the raw value on stdout for capture.
  std::fwrite(cred.data(), 1, cred.size(), stdout);
  std::fputc('\n', stdout);
  cred.clear();
  return kExitOk;
}

// Prints a non-granted reply and maps it to an exit code.
int ReportNonGrant(const json &r) {
  std::string status = r.value("status", "error");
  // Echo the reply as-is (never contains a credential for these statuses).
  std::fprintf(stdout, "%s\n", r.dump().c_str());
  if (status == "question")
    return kExitQuestion;
  if (status == "denied")
    return kExitDenied;
  return kExitError;
}

int Dispatch(const json &request, const std::vector<std::string> &command) {
  auto r = Send(request);
  if (!r.ok()) {
    std::fprintf(stderr, "prout: %s\n",
                 std::string(r.status().message()).c_str());
    return kExitError;
  }
  if (r->value("status", "") == "granted")
    return UseGranted(*r, command);
  return ReportNonGrant(*r);
}

} // namespace

int CmdRun(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  std::string service = a.Get("service");
  if (!a.Has("lease") && service.empty()) {
    std::fprintf(
        stderr, "usage: prout run --service <s> --intent \"<why>\" "
                "[--agent <name>] -- <cmd...>\n"
                "       prout run --lease <id> [--agent <name>] -- <cmd...>\n");
    return kExitError;
  }
  if (a.command.empty()) {
    std::fprintf(stderr, "prout: run requires a command after `--`\n");
    return kExitError;
  }

  json req;
  if (a.Has("lease")) {
    req = {{"op", "reuse"},
           {"lease_id", a.Get("lease")},
           {"agent", a.Get("agent", "agent")}};
  } else {
    req = {{"op", "run"},
           {"service", service},
           {"intent", a.Get("intent")},
           {"agent", a.Get("agent", "agent")}};
  }
  return Dispatch(req, a.command);
}

int CmdGet(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  std::string service = a.Get("service");
  if (service.empty()) {
    std::fprintf(stderr, "usage: prout get --service <s> --intent \"<why>\" "
                         "[--agent <name>]\n");
    return kExitError;
  }
  json req = {{"op", "get"},
              {"service", service},
              {"intent", a.Get("intent")},
              {"agent", a.Get("agent", "agent")}};
  return Dispatch(req, /*command=*/{});
}

int CmdAnswer(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  if (a.positional.size() < 2) {
    std::fprintf(stderr, "usage: prout answer <negotiation-id> \"<text>\" "
                         "[-- <cmd...>]\n");
    return kExitError;
  }
  json req = {{"op", "answer"},
              {"negotiation_id", a.positional[0]},
              {"answer", a.positional[1]},
              {"agent", a.Get("agent", "agent")}};
  return Dispatch(req, a.command);
}

} // namespace prout

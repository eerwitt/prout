// Client-side subcommands. Negotiation commands only print safe metadata.
// Credential bytes are requested only by final expose or execute delivery.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
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
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
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

absl::StatusOr<json> Send(const json &request) {
  auto resp = IpcRequest(SocketPath(), request.dump());
  if (!resp.ok())
    return resp.status();
  json j = json::parse(*resp, nullptr, false);
  if (j.is_discarded())
    return absl::InternalError("bad response from daemon");
  return j;
}

int ReportMetadata(const json &r) {
  std::string status = r.value("status", "error");
  std::fprintf(stdout, "%s\n", r.dump().c_str());
  if (status == "question")
    return kExitQuestion;
  if (status == "denied")
    return kExitDenied;
  if (status == "error")
    return kExitError;
  return kExitOk;
}

int DispatchMetadata(const json &request) {
  auto r = Send(request);
  if (!r.ok()) {
    std::fprintf(stderr, "prout: %s\n",
                 std::string(r.status().message()).c_str());
    return kExitError;
  }
  return ReportMetadata(*r);
}

std::string JoinCommand(const std::vector<std::string> &command) {
  std::string out;
  for (const auto &part : command) {
    if (!out.empty())
      out += " ";
    out += part;
  }
  return out;
}

class Redactor {
public:
  explicit Redactor(std::string secret) : secret_(std::move(secret)) {}

  void Write(const char *data, std::size_t size) {
    if (secret_.empty()) {
      std::fwrite(data, 1, size, stdout);
      return;
    }
    pending_.append(data, size);
    Drain(false);
  }

  void Finish() { Drain(true); }
  bool redacted() const { return redacted_; }

private:
  void Drain(bool finish) {
    while (true) {
      std::size_t pos = pending_.find(secret_);
      if (pos != std::string::npos) {
        std::fwrite(pending_.data(), 1, pos, stdout);
        std::string stars(secret_.size(), '*');
        std::fwrite(stars.data(), 1, stars.size(), stdout);
        pending_.erase(0, pos + secret_.size());
        redacted_ = true;
        continue;
      }
      const std::size_t keep = finish ? 0 : secret_.size() - 1;
      if (pending_.size() <= keep)
        return;
      const std::size_t emit = pending_.size() - keep;
      std::fwrite(pending_.data(), 1, emit, stdout);
      pending_.erase(0, emit);
      return;
    }
  }

  std::string secret_;
  std::string pending_;
  bool redacted_ = false;
};

#if defined(_WIN32)
std::string QuoteWindowsArg(const std::string &arg) {
  if (arg.empty() || arg.find_first_of(" \t\n\v\"") != std::string::npos) {
    std::string out = "\"";
    int backslashes = 0;
    for (char c : arg) {
      if (c == '\\') {
        ++backslashes;
        continue;
      }
      if (c == '"') {
        out.append(static_cast<std::size_t>(backslashes * 2 + 1), '\\');
        out.push_back('"');
      } else {
        out.append(static_cast<std::size_t>(backslashes), '\\');
        out.push_back(c);
      }
      backslashes = 0;
    }
    out.append(static_cast<std::size_t>(backslashes * 2), '\\');
    out.push_back('"');
    return out;
  }
  return arg;
}

std::string WindowsCommandLine(const std::vector<std::string> &command) {
  std::string out;
  for (const auto &arg : command) {
    if (!out.empty())
      out.push_back(' ');
    out += QuoteWindowsArg(arg);
  }
  return out;
}
#endif

int SpawnChildFiltered(const std::vector<std::string> &command,
                       const std::string &env_var, SecureBuffer &cred,
                       bool *redacted) {
  if (command.empty())
    return 127;

#if defined(_WIN32)
  HANDLE read_handle = nullptr;
  HANDLE write_handle = nullptr;
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe(&read_handle, &write_handle, &sa, 0))
    return 127;
  SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = write_handle;
  si.hStdError = write_handle;
  PROCESS_INFORMATION pi{};
  std::string cmdline = WindowsCommandLine(command);
  SetEnv(env_var, cred.c_str());
  BOOL created = CreateProcessA(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                                0, nullptr, nullptr, &si, &pi);
  UnsetEnv(env_var);
  CloseHandle(write_handle);
  if (!created) {
    CloseHandle(read_handle);
    std::fprintf(stderr, "prout: failed to run '%s'\n", command[0].c_str());
    return 127;
  }
  Redactor filter(std::string(cred.c_str(), cred.size()));
  std::thread reader([&] {
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(read_handle, buf, sizeof(buf), &n, nullptr) && n > 0)
      filter.Write(buf, static_cast<std::size_t>(n));
    CloseHandle(read_handle);
  });
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  reader.join();
  filter.Finish();
  if (redacted)
    *redacted = filter.redacted();
  return static_cast<int>(exit_code);
#else
  std::vector<char *> argv;
  for (const auto &a : command)
    argv.push_back(const_cast<char *>(a.c_str()));
  argv.push_back(nullptr);
  int pipefd[2];
  if (pipe(pipefd) != 0)
    return 127;
  SetEnv(env_var, cred.c_str());
  pid_t pid = fork();
  if (pid < 0) {
    UnsetEnv(env_var);
    close(pipefd[0]);
    close(pipefd[1]);
    return 127;
  }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    execvp(argv[0], argv.data());
    _exit(127);
  }
  UnsetEnv(env_var);
  close(pipefd[1]);
  Redactor filter(std::string(cred.c_str(), cred.size()));
  std::thread reader([&] {
    char buf[4096];
    ssize_t n = 0;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
      filter.Write(buf, static_cast<std::size_t>(n));
    close(pipefd[0]);
  });
  int status = 0;
  waitpid(pid, &status, 0);
  reader.join();
  filter.Finish();
  if (redacted)
    *redacted = filter.redacted();
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
#endif
}

int ExecuteDelivery(const json &r) {
  std::string env_var = r.value("env_var", "");
  std::string conversation_id = r.value("conversation_id", "");
  std::vector<std::string> command =
      r.value("command", std::vector<std::string>{});
  SecureBuffer cred;
  {
    std::string c = r.value("credential", "");
    cred.assign(c);
    SecureZero(c.data(), c.size());
  }
  bool redacted = false;
  int code = SpawnChildFiltered(command, env_var, cred, &redacted);
  cred.clear();
  auto ack = Send({{"op", "execute_result"},
                   {"conversation_id", conversation_id},
                   {"child_exit_code", code},
                   {"redacted", redacted}});
  (void)ack;
  return code;
}

} // namespace

int CmdRun(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  if (a.Has("lease")) {
    std::fprintf(stderr, "usage: prout execute --lease <id>\n");
    return kExitError;
  }

  if (a.Has("conversation")) {
    if (!a.Has("details")) {
      std::fprintf(stderr, "usage: prout run --conversation <id> --details "
                           "<text> [--agent <name>]\n");
      return kExitError;
    }
    return DispatchMetadata({{"op", "continue"},
                             {"kind", "run"},
                             {"conversation_id", a.Get("conversation")},
                             {"details", a.Get("details")},
                             {"agent", a.Get("agent", "agent")}});
  }

  std::string service = a.Get("service");
  if (service.empty() || !a.Has("intent") || a.command.empty()) {
    std::fprintf(stderr, "usage: prout run --service <s> --intent \"<why>\" "
                         "[--agent <name>] -- <cmd...>\n");
    return kExitError;
  }
  return DispatchMetadata({{"op", "negotiate"},
                           {"kind", "run"},
                           {"service", service},
                           {"intent", a.Get("intent")},
                           {"agent", a.Get("agent", "agent")},
                           {"command", a.command},
                           {"command_summary", JoinCommand(a.command)}});
}

int CmdExpose(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  if (a.Has("lease")) {
    if (a.Has("details") || a.Has("conversation")) {
      std::fprintf(stderr, "usage: prout expose --lease <id>\n");
      return kExitError;
    }
    auto r = Send({{"op", "expose_final"},
                   {"lease_id", a.Get("lease")},
                   {"agent", a.Get("agent", "agent")}});
    if (!r.ok()) {
      std::fprintf(stderr, "prout: %s\n",
                   std::string(r.status().message()).c_str());
      return kExitError;
    }
    if (r->value("status", "") != "deliver")
      return ReportMetadata(*r);
    SecureBuffer cred;
    {
      std::string c = r->value("credential", "");
      cred.assign(c);
      SecureZero(c.data(), c.size());
    }
    std::fwrite(cred.data(), 1, cred.size(), stdout);
    std::fputc('\n', stdout);
    cred.clear();
    return kExitOk;
  }
  if (a.Has("conversation") && !a.Has("details")) {
    std::fprintf(stderr, "usage: prout expose --lease <id>\n");
    return kExitError;
  }
  if (a.Has("conversation")) {
    return DispatchMetadata({{"op", "continue"},
                             {"kind", "expose"},
                             {"conversation_id", a.Get("conversation")},
                             {"details", a.Get("details")},
                             {"agent", a.Get("agent", "agent")}});
  }
  std::string service = a.Get("service");
  if (service.empty() || !a.Has("intent")) {
    std::fprintf(stderr, "usage: prout expose --service <s> --intent \"<why>\" "
                         "[--agent <name>]\n");
    return kExitError;
  }
  return DispatchMetadata({{"op", "negotiate"},
                           {"kind", "expose"},
                           {"service", service},
                           {"intent", a.Get("intent")},
                           {"agent", a.Get("agent", "agent")}});
}

int CmdExecute(const std::vector<std::string> &argv) {
  Args a = ParseArgs(argv);
  if (!a.Has("lease") || !a.command.empty()) {
    std::fprintf(stderr, "usage: prout execute --lease <id>\n");
    return kExitError;
  }
  auto r = Send({{"op", "execute"}, {"lease_id", a.Get("lease")}});
  if (!r.ok()) {
    std::fprintf(stderr, "prout: %s\n",
                 std::string(r.status().message()).c_str());
    return kExitError;
  }
  if (r->value("status", "") != "deliver")
    return ReportMetadata(*r);
  return ExecuteDelivery(*r);
}

} // namespace prout

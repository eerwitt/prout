// Entry points for each top-level prout subcommand. Each takes the argument
// vector *after* the subcommand token and returns a process exit code.
#pragma once

#include <string>
#include <vector>

namespace prout {

int CmdServe(const std::vector<std::string> &args);  // daemon
int CmdVault(const std::vector<std::string> &args);  // init/add/list (offline)
int CmdRun(const std::vector<std::string> &args);    // negotiate only
int CmdExpose(const std::vector<std::string> &args); // negotiate -> print value
int CmdExecute(const std::vector<std::string> &args); // approved run -> exec
int CmdAudit(const std::vector<std::string> &args);   // tail / verify

// Exit codes shared by client commands so agents can branch on them.
inline constexpr int kExitOk = 0;
inline constexpr int kExitError = 1;
inline constexpr int kExitQuestion = 10; // arbiter needs an answer
inline constexpr int kExitDenied = 11;   // arbiter denied

} // namespace prout

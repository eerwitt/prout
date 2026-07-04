// Resolves the well-known filesystem locations Prout uses, per-platform.
#pragma once

#include <string>

namespace prout {

// Directory holding the vault + audit logs. Override with $PROUT_HOME.
// Default: %LOCALAPPDATA%\prout on Windows, ~/.prout elsewhere.
std::string VaultDir();

// Path to the daemon's AF_UNIX socket. Lives under a runtime dir so it is
// owner-only and cleaned across reboots where possible.
std::string SocketPath();

// This machine's stable short identity, used to name its own audit log and
// attribute records. Derived from the hostname; overridable with
// $PROUT_MACHINE.
std::string MachineId();

// Ensures `dir` exists (creating parents). Returns true on success.
bool EnsureDir(const std::string &dir);

} // namespace prout

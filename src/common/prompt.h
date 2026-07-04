// Reads a secret from the terminal without echo. Falls back to
// $PROUT_PASSPHRASE when set, so the daemon can be started non-interactively
// (tests, demos).
#pragma once

#include <string>

namespace prout {

std::string ReadPassphrase(const std::string &prompt);
std::string ReadSecretLine(const std::string &prompt);
void ClearSensitiveTerminalArea();

} // namespace prout

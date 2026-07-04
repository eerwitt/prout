#include "common/prompt.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace prout {

std::string ReadPassphrase(const std::string &prompt) {
  if (const char *env = std::getenv("PROUT_PASSPHRASE"))
    return std::string(env);

  std::fputs(prompt.c_str(), stderr);
  std::fflush(stderr);

  std::string line;
#if defined(_WIN32)
  HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  bool changed = ::GetConsoleMode(h, &mode) != 0;
  if (changed)
    ::SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
  std::getline(std::cin, line);
  if (changed)
    ::SetConsoleMode(h, mode);
#else
  termios oldt{};
  bool changed = tcgetattr(STDIN_FILENO, &oldt) == 0;
  if (changed) {
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  }
  std::getline(std::cin, line);
  if (changed)
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  std::fputs("\n", stderr);
  return line;
}

} // namespace prout

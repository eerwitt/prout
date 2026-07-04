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
namespace {

std::string ReadNoEcho(const std::string &prompt) {
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

} // namespace

std::string ReadPassphrase(const std::string &prompt) {
  if (const char *env = std::getenv("PROUT_PASSPHRASE"))
    return std::string(env);
  return ReadNoEcho(prompt);
}

std::string ReadSecretLine(const std::string &prompt) {
  std::string line = ReadNoEcho(prompt);
  ClearSensitiveTerminalArea();
  std::fputs("credential captured [ok]\n", stderr);
  return line;
}

void ClearSensitiveTerminalArea() {
#if defined(_WIN32)
  HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (::GetConsoleScreenBufferInfo(h, &info)) {
    DWORD written = 0;
    COORD home{0, static_cast<SHORT>(info.dwCursorPosition.Y)};
    ::FillConsoleOutputCharacterA(h, ' ', info.dwSize.X, home, &written);
    ::SetConsoleCursorPosition(h, home);
    return;
  }
#endif
  std::fputs("\r\033[2K", stdout);
  std::fflush(stdout);
}

} // namespace prout

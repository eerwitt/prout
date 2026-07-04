#include "common/paths.h"

#include <cstdlib>
#include <filesystem>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace prout {
namespace fs = std::filesystem;

namespace {

std::string Env(const char *name) {
  const char *v = std::getenv(name);
  return v ? std::string(v) : std::string();
}

std::string HomeDir() {
#if defined(_WIN32)
  std::string h = Env("USERPROFILE");
  if (!h.empty())
    return h;
  std::string drive = Env("HOMEDRIVE");
  std::string path = Env("HOMEPATH");
  if (!drive.empty())
    return drive + path;
  return ".";
#else
  std::string h = Env("HOME");
  return h.empty() ? "." : h;
#endif
}

} // namespace

std::string VaultDir() {
  std::string over = Env("PROUT_HOME");
  if (!over.empty())
    return over;
#if defined(_WIN32)
  std::string base = Env("LOCALAPPDATA");
  if (base.empty())
    base = HomeDir();
  return (fs::path(base) / "prout").string();
#else
  return (fs::path(HomeDir()) / ".prout").string();
#endif
}

std::string SocketPath() {
  std::string over = Env("PROUT_SOCKET");
  if (!over.empty())
    return over;
#if defined(_WIN32)
  return (fs::path(VaultDir()) / "prout.sock").string();
#else
  std::string rt = Env("XDG_RUNTIME_DIR");
  if (!rt.empty())
    return (fs::path(rt) / "prout.sock").string();
  return (fs::path(VaultDir()) / "prout.sock").string();
#endif
}

std::string MachineId() {
  std::string over = Env("PROUT_MACHINE");
  if (!over.empty())
    return over;
#if defined(_WIN32)
  char buf[256];
  DWORD n = sizeof(buf);
  if (::GetComputerNameA(buf, &n))
    return std::string(buf, n);
  return "windows";
#else
  char buf[256];
  if (::gethostname(buf, sizeof(buf)) == 0)
    return std::string(buf);
  return "host";
#endif
}

bool EnsureDir(const std::string &dir) {
  std::error_code ec;
  if (dir.empty())
    return false;
  fs::create_directories(dir, ec);
  return !ec && fs::exists(dir);
}

} // namespace prout

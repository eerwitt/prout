#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <string>
#include <thread>

#include "daemon/lease.h"
#include "ipc/ipc.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <afunix.h>
using socket_t = SOCKET;
static constexpr socket_t kBadSock = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kBadSock = -1;
#endif

namespace fs = std::filesystem;

namespace {

void Fail(const std::string &message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

void Expect(bool condition, const std::string &message) {
  if (!condition)
    Fail(message);
}

void SetEnv(const char *name, const std::string &value) {
#if defined(_WIN32)
  if (::_putenv_s(name, value.c_str()) != 0)
    Fail(std::string("failed to set env ") + name);
#else
  if (::setenv(name, value.c_str(), 1) != 0)
    Fail(std::string("failed to set env ") + name);
#endif
}

void CloseSock(socket_t s) {
  if (s == kBadSock)
    return;
#if defined(_WIN32)
  ::closesocket(s);
#else
  ::close(s);
#endif
}

void EnsureSocketsReady() {
#if defined(_WIN32)
  WSADATA d;
  if (::WSAStartup(MAKEWORD(2, 2), &d) != 0)
    Fail("WSAStartup failed");
#endif
}

bool FillAddr(sockaddr_un *addr, const std::string &path) {
  std::memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr->sun_path))
    return false;
  std::memcpy(addr->sun_path, path.c_str(), path.size() + 1);
  return true;
}

void SendOversizedFrame(const std::string &socket_path) {
  socket_t s = ::socket(AF_UNIX, SOCK_STREAM, 0);
  Expect(s != kBadSock, "oversized client socket() failed");
  sockaddr_un addr;
  Expect(FillAddr(&addr, socket_path), "socket path too long in test");
  if (::connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    CloseSock(s);
    Fail("oversized client connect() failed");
  }
  const std::uint8_t header[4] = {0x00, 0x80, 0x00, 0x01};
#if defined(_WIN32)
  int sent =
      ::send(s, reinterpret_cast<const char *>(header), sizeof(header), 0);
#else
  ssize_t sent = ::send(s, header, sizeof(header), 0);
#endif
  CloseSock(s);
  Expect(sent == 4, "oversized frame header was not sent");
}

void TestLeases() {
  prout::LeaseTable leases;
  std::regex id_re("^lease-[0-9a-f]{64}$");
  std::set<std::string> ids;
  for (int i = 0; i < 256; ++i) {
    auto id = leases.Create("api", 60, 2);
    Expect(id.ok(),
           "lease creation failed: " + std::string(id.status().message()));
    Expect(std::regex_match(*id, id_re), "lease id was not opaque hex: " + *id);
    Expect(ids.insert(*id).second, "duplicate random lease id generated");
  }
  Expect(ids.find("lease-1") == ids.end(), "lease ids are still sequential");
  std::uint32_t uses_left = 0;
  Expect(leases.Consume("lease-1", "", &uses_left) ==
             prout::LeaseTable::Status::kUnknown,
         "guessed sequential lease id was accepted");
}

void TestIpc(const fs::path &root) {
  EnsureSocketsReady();
  fs::path home = root / "home";
  SetEnv("PROUT_HOME", home.string());
  SetEnv("PROUT_SOCKET", "");
  fs::path socket_path = home / "prout.sock";
  fs::create_directories(home);
  {
    std::ofstream stale(socket_path);
    stale << "stale";
  }

  prout::IpcServer server;
  auto st = server.Listen(socket_path.string());
  Expect(st.ok(), "Listen failed: " + std::string(st.message()));
  Expect(fs::exists(home), "socket parent directory was not created");

#if !defined(_WIN32)
  struct stat parent_st{};
  struct stat socket_st{};
  Expect(::stat(home.string().c_str(), &parent_st) == 0,
         "could not stat socket parent");
  Expect((parent_st.st_mode & 0777) == 0700, "socket parent is not owner-only");
  Expect(::stat(socket_path.string().c_str(), &socket_st) == 0,
         "could not stat socket path");
  Expect((socket_st.st_mode & 0777) == 0600, "socket is not owner-only");
#endif

  std::atomic<bool> stop{false};
  std::atomic<int> handled{0};
  std::thread serving([&] {
    auto serve_status = server.Serve(
        [&](const std::string &request) {
          handled.fetch_add(1);
          if (request == "stop")
            stop.store(true);
          return std::string("ok");
        },
        [&] { return stop.load(); });
    if (!serve_status.ok())
      Fail("Serve failed: " + std::string(serve_status.message()));
  });

  auto ok = prout::IpcRequest(socket_path.string(), "ping");
  Expect(ok.ok() && *ok == "ok", "normal IPC request failed");
  Expect(handled.load() == 1, "normal IPC request was not handled once");

  SendOversizedFrame(socket_path.string());
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  Expect(handled.load() == 1, "oversized frame reached the handler");

  auto stopped = prout::IpcRequest(socket_path.string(), "stop");
  Expect(stopped.ok(), "stop request failed");
  serving.join();
  server.Close();
}

} // namespace

int main() {
  fs::path root =
      fs::temp_directory_path() /
      ("prout-hardening-" +
       std::to_string(static_cast<unsigned long long>(
           std::chrono::steady_clock::now().time_since_epoch().count())));
  fs::create_directories(root);
  TestLeases();
  TestIpc(root);
  std::error_code ec;
  fs::remove_all(root, ec);
  return 0;
}

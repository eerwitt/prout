#include "ipc/ipc.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "common/paths.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <afunix.h>
#include <accctrl.h>
#include <aclapi.h>
using socket_t = SOCKET;
static constexpr socket_t kBadSock = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kBadSock = -1;
#endif

namespace prout {
namespace fs = std::filesystem;
namespace {

constexpr std::uint32_t kMaxFrame = 8u * 1024 * 1024;
constexpr int kDefaultSocketTimeoutMs = 3000;
constexpr int kClientResponseTimeoutMs = 120000;

enum class FrameReadResult { kOk, kClosed, kOversized };

struct WinsockGuard {
#if defined(_WIN32)
  WinsockGuard() {
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
  }
#endif
};

void EnsureWinsock() {
#if defined(_WIN32)
  static WinsockGuard g;
  (void)g;
#endif
}

void SetSocketTimeouts(socket_t s, int recv_ms = kDefaultSocketTimeoutMs,
                       int send_ms = kDefaultSocketTimeoutMs) {
#if defined(_WIN32)
  DWORD recv_timeout = static_cast<DWORD>(recv_ms);
  DWORD send_timeout = static_cast<DWORD>(send_ms);
  ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char *>(&recv_timeout),
               sizeof(recv_timeout));
  ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char *>(&send_timeout),
               sizeof(send_timeout));
#else
  timeval recv_timeout{};
  recv_timeout.tv_sec = recv_ms / 1000;
  recv_timeout.tv_usec = (recv_ms % 1000) * 1000;
  timeval send_timeout{};
  send_timeout.tv_sec = send_ms / 1000;
  send_timeout.tv_usec = (send_ms % 1000) * 1000;
  ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
  ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
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

std::string SockErr() {
#if defined(_WIN32)
  return "winsock error " + std::to_string(WSAGetLastError());
#else
  return std::string(std::strerror(errno));
#endif
}

#if defined(_WIN32)
std::string WinErr(DWORD err) { return "windows error " + std::to_string(err); }
#endif

bool FillAddr(sockaddr_un *addr, const std::string &path) {
  std::memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr->sun_path))
    return false;
  std::memcpy(addr->sun_path, path.c_str(), path.size() + 1);
  return true;
}

bool ReadN(socket_t s, void *buf, std::size_t n) {
  auto *p = static_cast<char *>(buf);
  std::size_t got = 0;
  while (got < n) {
#if defined(_WIN32)
    int r = ::recv(s, p + got, static_cast<int>(n - got), 0);
#else
    ssize_t r = ::recv(s, p + got, n - got, 0);
#endif
    if (r <= 0)
      return false;
    got += static_cast<std::size_t>(r);
  }
  return true;
}

bool WriteN(socket_t s, const void *buf, std::size_t n) {
  const auto *p = static_cast<const char *>(buf);
  std::size_t sent = 0;
  while (sent < n) {
#if defined(_WIN32)
    int r = ::send(s, p + sent, static_cast<int>(n - sent), 0);
#else
    ssize_t r = ::send(s, p + sent, n - sent, 0);
#endif
    if (r <= 0)
      return false;
    sent += static_cast<std::size_t>(r);
  }
  return true;
}

FrameReadResult ReadFrameChecked(socket_t s, std::string *out) {
  std::uint8_t hdr[4];
  if (!ReadN(s, hdr, 4))
    return FrameReadResult::kClosed;
  std::uint32_t len = (std::uint32_t(hdr[0]) << 24) |
                      (std::uint32_t(hdr[1]) << 16) |
                      (std::uint32_t(hdr[2]) << 8) | std::uint32_t(hdr[3]);
  if (len > kMaxFrame)
    return FrameReadResult::kOversized;
  out->resize(len);
  if (len != 0 && !ReadN(s, out->data(), len))
    return FrameReadResult::kClosed;
  return FrameReadResult::kOk;
}

bool ReadFrame(socket_t s, std::string *out) {
  return ReadFrameChecked(s, out) == FrameReadResult::kOk;
}

bool WriteFrame(socket_t s, const std::string &payload) {
  if (payload.size() > kMaxFrame)
    return false;
  std::uint32_t len = static_cast<std::uint32_t>(payload.size());
  std::uint8_t hdr[4] = {std::uint8_t(len >> 24), std::uint8_t(len >> 16),
                         std::uint8_t(len >> 8), std::uint8_t(len)};
  if (!WriteN(s, hdr, 4))
    return false;
  return payload.empty() || WriteN(s, payload.data(), payload.size());
}

#if defined(_WIN32)
absl::Status SetOwnerOnlyAcl(const fs::path &path, bool directory) {
  std::string path_string = path.string();
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR sd = nullptr;
  DWORD err = ::GetNamedSecurityInfoA(path_string.data(), SE_FILE_OBJECT,
                                      OWNER_SECURITY_INFORMATION, &owner,
                                      nullptr, nullptr, nullptr, &sd);
  if (err != ERROR_SUCCESS)
    return absl::PermissionDeniedError("cannot read socket path owner: " +
                                       WinErr(err));

  EXPLICIT_ACCESSA access{};
  access.grfAccessPermissions = GENERIC_ALL;
  access.grfAccessMode = SET_ACCESS;
  access.grfInheritance =
      directory ? (SUB_CONTAINERS_AND_OBJECTS_INHERIT | OBJECT_INHERIT_ACE)
                : NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_USER;
  access.Trustee.ptstrName = static_cast<LPSTR>(owner);

  PACL dacl = nullptr;
  err = ::SetEntriesInAclA(1, &access, nullptr, &dacl);
  if (err == ERROR_SUCCESS) {
    err = ::SetNamedSecurityInfoA(path_string.data(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION |
                                      PROTECTED_DACL_SECURITY_INFORMATION,
                                  nullptr, nullptr, dacl, nullptr);
  }
  if (dacl)
    ::LocalFree(dacl);
  if (sd)
    ::LocalFree(sd);
  if (err != ERROR_SUCCESS)
    return absl::PermissionDeniedError("cannot set owner-only socket ACL: " +
                                       WinErr(err));
  return absl::OkStatus();
}
#endif

absl::Status SecureSocketParent(const fs::path &socket_path) {
  fs::path parent = socket_path.parent_path();
  if (parent.empty())
    return absl::InvalidArgumentError("socket path has no parent directory");
  if (!EnsureDir(parent.string()))
    return absl::UnavailableError("cannot create socket directory");

#if defined(_WIN32)
  return SetOwnerOnlyAcl(parent, /*directory=*/true);
#else
  struct stat st{};
  if (::lstat(parent.string().c_str(), &st) != 0)
    return absl::UnavailableError("cannot stat socket directory: " + SockErr());
  if (!S_ISDIR(st.st_mode))
    return absl::InvalidArgumentError("socket parent is not a directory");
  if (st.st_uid != ::geteuid())
    return absl::PermissionDeniedError(
        "socket directory is not owned by this user");
  if (::chmod(parent.string().c_str(), S_IRWXU) != 0)
    return absl::PermissionDeniedError(
        "cannot set socket directory permissions: " + SockErr());
  return absl::OkStatus();
#endif
}

absl::Status SecureSocketPath(const fs::path &socket_path) {
#if defined(_WIN32)
  return SetOwnerOnlyAcl(socket_path, /*directory=*/false);
#else
  if (::chmod(socket_path.string().c_str(), S_IRUSR | S_IWUSR) != 0)
    return absl::PermissionDeniedError("cannot set socket permissions: " +
                                       SockErr());
  return absl::OkStatus();
#endif
}

absl::Status ValidatePeer(socket_t c) {
#if defined(_WIN32)
  (void)c;
  return absl::OkStatus();
#elif defined(SO_PEERCRED)
  struct ucred cred{};
  socklen_t len = sizeof(cred);
  if (::getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
    return absl::PermissionDeniedError("cannot validate peer credentials: " +
                                       SockErr());
  if (cred.uid != ::geteuid())
    return absl::PermissionDeniedError("peer uid does not match daemon uid");
  return absl::OkStatus();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__OpenBSD__)
  uid_t uid = 0;
  gid_t gid = 0;
  if (::getpeereid(c, &uid, &gid) != 0)
    return absl::PermissionDeniedError("cannot validate peer credentials: " +
                                       SockErr());
  if (uid != ::geteuid())
    return absl::PermissionDeniedError("peer uid does not match daemon uid");
  return absl::OkStatus();
#else
  (void)c;
  return absl::OkStatus();
#endif
}

} // namespace

absl::StatusOr<std::string> IpcRequest(const std::string &socket_path,
                                       const std::string &request) {
  EnsureWinsock();
  socket_t s = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (s == kBadSock)
    return absl::InternalError("socket(): " + SockErr());
  SetSocketTimeouts(s, kClientResponseTimeoutMs);

  sockaddr_un addr;
  if (!FillAddr(&addr, socket_path)) {
    CloseSock(s);
    return absl::InvalidArgumentError("socket path too long");
  }
  if (::connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    CloseSock(s);
    return absl::UnavailableError(
        "cannot reach prout daemon (is `prout serve` running?): " + SockErr());
  }
  if (!WriteFrame(s, request)) {
    CloseSock(s);
    return absl::InternalError("failed to send request");
  }
  std::string resp;
  FrameReadResult read = ReadFrameChecked(s, &resp);
  if (read != FrameReadResult::kOk) {
    CloseSock(s);
    if (read == FrameReadResult::kOversized)
      return absl::ResourceExhaustedError(
          "response frame exceeds maximum size");
    return absl::InternalError("failed to read response");
  }
  CloseSock(s);
  return resp;
}

absl::Status IpcServer::Listen(const std::string &socket_path) {
  EnsureWinsock();
  fs::path sock_path(socket_path);
  auto secure_parent = SecureSocketParent(sock_path);
  if (!secure_parent.ok())
    return secure_parent;

  std::error_code ec;
  auto probe = IpcRequest(socket_path, "{\"op\":\"ping\"}");
  if (probe.ok()) {
    return absl::AlreadyExistsError("a prout daemon is already serving on " +
                                    socket_path);
  }
  if (fs::exists(sock_path, ec)) {
    fs::remove(sock_path, ec);
    if (ec) {
      return absl::UnavailableError("cannot remove stale socket: " +
                                    ec.message());
    }
  }

  socket_t s = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (s == kBadSock)
    return absl::InternalError("socket(): " + SockErr());
  SetSocketTimeouts(s);

  sockaddr_un addr;
  if (!FillAddr(&addr, socket_path)) {
    CloseSock(s);
    return absl::InvalidArgumentError("socket path too long");
  }
  bool bound =
      ::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
#if defined(_WIN32)
  int bind_error = bound ? 0 : WSAGetLastError();
  if (!bound && bind_error == WSAEADDRINUSE) {
    CloseSock(s);
    fs::remove(sock_path, ec);
    if (ec) {
      return absl::UnavailableError("cannot remove stale socket: " +
                                    ec.message());
    }
    s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == kBadSock)
      return absl::InternalError("socket(): " + SockErr());
    SetSocketTimeouts(s);
    bound = ::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
    bind_error = bound ? 0 : WSAGetLastError();
  }
#endif
  if (!bound) {
#if defined(_WIN32)
    std::string err = "winsock error " + std::to_string(bind_error);
#else
    std::string err = SockErr();
#endif
    CloseSock(s);
    return absl::UnavailableError(
        "bind() failed (another daemon already running?): " + err);
  }
  auto secure_socket = SecureSocketPath(sock_path);
  if (!secure_socket.ok()) {
    CloseSock(s);
    fs::remove(sock_path, ec);
    return secure_socket;
  }
  if (::listen(s, 8) != 0) {
    CloseSock(s);
    fs::remove(sock_path, ec);
    return absl::InternalError("listen(): " + SockErr());
  }
  socket_path_ = socket_path;
  fd_ = static_cast<std::intptr_t>(s);
  return absl::OkStatus();
}

absl::Status IpcServer::Serve(const Handler &handler,
                              const std::function<bool()> &stop) {
  if (fd_ == -1)
    return absl::FailedPreconditionError("not listening");
  socket_t srv = static_cast<socket_t>(fd_);
  while (!stop()) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(srv, &readfds);
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
#if defined(_WIN32)
    int ready = ::select(0, &readfds, nullptr, nullptr, &tv);
#else
    int ready = ::select(srv + 1, &readfds, nullptr, nullptr, &tv);
#endif
    if (ready == 0)
      continue;
    if (ready < 0) {
      if (stop())
        break;
      continue;
    }

    socket_t c = ::accept(srv, nullptr, nullptr);
    if (c == kBadSock) {
      if (stop())
        break;
      continue;
    }
    SetSocketTimeouts(c);
    if (!ValidatePeer(c).ok()) {
      CloseSock(c);
      continue;
    }
    std::string req;
    FrameReadResult read = ReadFrameChecked(c, &req);
    if (read == FrameReadResult::kOk) {
      std::string resp = handler(req);
      WriteFrame(c, resp);
    }
    CloseSock(c);
  }
  return absl::OkStatus();
}

void IpcServer::Close() {
  if (fd_ != -1) {
    CloseSock(static_cast<socket_t>(fd_));
    fd_ = -1;
  }
  if (!socket_path_.empty()) {
    std::error_code ec;
    fs::remove(socket_path_, ec);
    socket_path_.clear();
  }
}

} // namespace prout

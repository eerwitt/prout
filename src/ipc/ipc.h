// Minimal AF_UNIX transport shared by the CLI client and the daemon. Messages
// are length-prefixed JSON: a 4-byte big-endian length followed by that many
// UTF-8 bytes. No HTTP: on loopback the transport cost is negligible next to
// inference, and a domain socket avoids a TCP port and any firewall prompt.
#pragma once

#include <functional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace prout {

// One-shot client request: connect to `socket_path`, send `request` as a frame,
// read one response frame, close. Returns the response payload.
absl::StatusOr<std::string> IpcRequest(const std::string &socket_path,
                                       const std::string &request);

// Blocking accept loop. For each connection, reads one request frame, calls
// `handler`, and writes its return value as the response frame. Serialized:
// one connection at a time (single model, single user). Runs until `stop`
// returns true between connections, or a fatal socket error occurs.
class IpcServer {
public:
  using Handler = std::function<std::string(const std::string &request)>;

  absl::Status Listen(const std::string &socket_path);
  absl::Status Serve(const Handler &handler, const std::function<bool()> &stop);
  void Close();
  ~IpcServer() { Close(); }

private:
  std::string socket_path_;
  std::intptr_t fd_ = -1; // SOCKET on Windows, int fd on POSIX
};

} // namespace prout

// In-memory lease table held by the daemon. A lease is the result of a granted
// negotiation: it authorizes a bounded number of credential deliveries within a
// time window. Leases never persist to disk.
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>

#include "absl/status/statusor.h"

namespace prout {

struct Lease {
  std::string id;
  std::string service;
  std::chrono::steady_clock::time_point expires_at;
  std::uint32_t uses_remaining = 0;
};

class LeaseTable {
public:
  absl::StatusOr<std::string> Create(const std::string &service,
                                     std::uint32_t ttl_seconds,
                                     std::uint32_t max_uses);

  enum class Status { kOk, kUnknown, kExpired, kExhausted, kWrongService };

  Status Consume(const std::string &id, const std::string &expect_service,
                 std::uint32_t *uses_left_out,
                 std::string *service_out = nullptr);

private:
  std::map<std::string, Lease> leases_;
};

} // namespace prout

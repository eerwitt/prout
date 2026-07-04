#include "daemon/lease.h"

#include <array>

#include "vault/crypto.h"

namespace prout {

absl::StatusOr<std::string> LeaseTable::Create(const std::string &service,
                                               std::uint32_t ttl_seconds,
                                               std::uint32_t max_uses) {
  std::string id;
  do {
    std::array<std::uint8_t, 32> bytes{};
    auto st = RandomBytes(bytes.data(), bytes.size());
    if (!st.ok())
      return st;
    id = "lease-" + ToHex(bytes.data(), bytes.size());
  } while (leases_.find(id) != leases_.end());

  Lease l;
  l.id = id;
  l.service = service;
  l.expires_at =
      std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds);
  l.uses_remaining = max_uses;
  leases_[l.id] = l;
  return l.id;
}

LeaseTable::Status LeaseTable::Consume(const std::string &id,
                                       const std::string &expect_service,
                                       std::uint32_t *uses_left_out,
                                       std::string *service_out) {
  auto it = leases_.find(id);
  if (it == leases_.end())
    return Status::kUnknown;
  Lease &l = it->second;
  if (!expect_service.empty() && l.service != expect_service)
    return Status::kWrongService;
  if (std::chrono::steady_clock::now() >= l.expires_at) {
    if (service_out)
      *service_out = l.service;
    leases_.erase(it);
    return Status::kExpired;
  }
  if (l.uses_remaining == 0) {
    if (service_out)
      *service_out = l.service;
    leases_.erase(it);
    return Status::kExhausted;
  }
  if (service_out)
    *service_out = l.service;
  --l.uses_remaining;
  if (uses_left_out)
    *uses_left_out = l.uses_remaining;
  if (l.uses_remaining == 0)
    leases_.erase(it);
  return Status::kOk;
}

} // namespace prout

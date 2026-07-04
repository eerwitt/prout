#include "audit/audit.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "common/paths.h"
#include "nlohmann/json.hpp"
#include "vault/crypto.h"

namespace prout {
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string NowIso8601() {
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

// The canonical bytes that get hashed: the record with its own hash field
// omitted, serialized deterministically (ordered_json preserves insert order).
std::string Canonical(const nlohmann::ordered_json &rec) {
  nlohmann::ordered_json copy = rec;
  copy.erase("hash");
  return copy.dump();
}

} // namespace

AuditLog::AuditLog(std::string dir)
    : dir_(std::move(dir)), machine_(MachineId()) {}

std::string AuditLog::Path() const {
  return (fs::path(dir_) / ("audit-" + machine_ + ".jsonl")).string();
}

absl::Status AuditLog::Append(const AuditEntry &e) {
  if (!EnsureDir(dir_))
    return absl::InternalError("cannot create " + dir_);

  // Find the previous hash (last line of our own file).
  std::string prev = "GENESIS";
  {
    std::ifstream f(Path());
    std::string line, last;
    while (std::getline(f, line)) {
      if (!line.empty())
        last = line;
    }
    if (!last.empty()) {
      json j = json::parse(last, nullptr, false);
      if (!j.is_discarded() && j.contains("hash"))
        prev = j["hash"].get<std::string>();
    }
  }

  nlohmann::ordered_json rec;
  rec["ts"] = NowIso8601();
  rec["machine"] = machine_;
  rec["agent"] = e.agent;
  rec["service"] = e.service;
  rec["intent"] = e.intent;
  rec["transcript"] = e.transcript;
  rec["verdict"] = e.verdict;
  rec["rationale"] = e.rationale;
  rec["ttl_seconds"] = e.ttl_seconds;
  rec["max_uses"] = e.max_uses;
  rec["disclosure"] = e.disclosure;
  rec["prev_hash"] = prev;
  rec["hash"] = Blake2bHex(prev, Canonical(rec));

  std::ofstream f(Path(), std::ios::app);
  if (!f)
    return absl::InternalError("cannot append to " + Path());
  f << rec.dump() << "\n";
  if (!f)
    return absl::InternalError("append write failed");
  return absl::OkStatus();
}

absl::StatusOr<std::vector<std::string>> AuditLog::Tail(int n) const {
  std::ifstream f(Path());
  if (!f)
    return std::vector<std::string>{}; // no log yet is not an error
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(f, line))
    if (!line.empty())
      lines.push_back(line);

  std::vector<std::string> out;
  int start = std::max(0, static_cast<int>(lines.size()) - n);
  for (int i = start; i < static_cast<int>(lines.size()); ++i) {
    json j = json::parse(lines[i], nullptr, false);
    if (j.is_discarded())
      continue;
    std::ostringstream s;
    s << j.value("ts", "?") << "  " << j.value("verdict", "?") << "  "
      << j.value("agent", "?") << " -> " << j.value("service", "?");
    std::string rat = j.value("rationale", "");
    if (!rat.empty())
      s << "  (" << rat << ")";
    if (j.value("verdict", "") == "granted")
      s << "  [ttl=" << j.value("ttl_seconds", 0)
        << "s uses=" << j.value("max_uses", 0) << "]";
    out.push_back(s.str());
  }
  return out;
}

absl::Status AuditLog::Verify() const {
  std::ifstream f(Path());
  if (!f)
    return absl::OkStatus(); // empty chain is trivially valid
  std::string line, prev = "GENESIS";
  int lineno = 0;
  while (std::getline(f, line)) {
    if (line.empty())
      continue;
    ++lineno;
    nlohmann::ordered_json j =
        nlohmann::ordered_json::parse(line, nullptr, false);
    if (j.is_discarded())
      return absl::DataLossError("record " + std::to_string(lineno) +
                                 " is not valid JSON");
    if (j.value("prev_hash", "") != prev)
      return absl::DataLossError("chain break at record " +
                                 std::to_string(lineno) + " (prev_hash)");
    std::string want = Blake2bHex(prev, Canonical(j));
    if (j.value("hash", "") != want)
      return absl::DataLossError("tampered record at line " +
                                 std::to_string(lineno));
    prev = j.value("hash", "");
  }
  return absl::OkStatus();
}

} // namespace prout

#include "vault/vault.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "common/paths.h"
#include "nlohmann/json.hpp"

namespace prout {
namespace fs = std::filesystem;
using json = nlohmann::json;

std::string DisclosureName(Disclosure d) {
  return d == Disclosure::kReveal ? "reveal" : "inject";
}

absl::StatusOr<Disclosure> ParseDisclosure(const std::string &s) {
  if (s == "inject")
    return Disclosure::kInject;
  if (s == "reveal")
    return Disclosure::kReveal;
  return absl::InvalidArgumentError("disclosure must be 'inject' or 'reveal'");
}

namespace {
constexpr int kBodySchemaVersion = 2;

std::string VaultFile(const std::string &dir) {
  return (fs::path(dir) / "vault.json").string();
}

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

absl::StatusOr<std::string> ReadFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f)
    return absl::NotFoundError("cannot open " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

absl::Status WriteFileAtomic(const std::string &path, const std::string &data) {
  std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f)
      return absl::InternalError("cannot write " + tmp);
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!f)
      return absl::InternalError("write failed for " + tmp);
  }
  std::error_code ec;
  fs::rename(tmp, path, ec);
  if (ec) {
    fs::remove(path, ec);
    fs::rename(tmp, path, ec);
  }
  if (ec)
    return absl::InternalError("atomic replace failed: " + ec.message());
  return absl::OkStatus();
}

std::string RequiredString(const json &j, const char *field,
                           const std::string &service) {
  if (!j.contains(field) || !j[field].is_string())
    throw std::runtime_error("service '" + service +
                             "' missing required field '" + field + "'");
  return j[field].get<std::string>();
}

std::uint32_t RequiredU32(const json &j, const char *field,
                          const std::string &service) {
  if (!j.contains(field) || !j[field].is_number_unsigned())
    throw std::runtime_error("service '" + service +
                             "' missing required field '" + field + "'");
  return j[field].get<std::uint32_t>();
}

std::string SerializeBody(const std::map<std::string, Service> &services) {
  json body;
  body["schema_version"] = kBodySchemaVersion;
  json svc = json::object();
  for (const auto &[name, s] : services) {
    json j;
    j["name"] = s.name;
    j["inject_env"] = s.inject_env;
    j["disclosure"] = DisclosureName(s.disclosure);
    j["policy"] = {{"max_ttl_seconds", s.policy.max_ttl_seconds},
                   {"max_uses", s.policy.max_uses},
                   {"description", s.policy.description},
                   {"guidance", s.policy.guidance}};
    j["website_url"] = s.website_url;
    j["website_host"] = s.website_host;
    j["company"] = s.company;
    j["details"] = s.details;
    j["expires_at"] = s.expires_at;
    j["created_at"] = s.created_at;
    j["updated_at"] = s.updated_at;
    j["update_timestamps"] = s.update_timestamps;
    j["credential"] =
        std::string(reinterpret_cast<const char *>(s.credential.data()),
                    s.credential.size());
    svc[name] = std::move(j);
  }
  body["services"] = std::move(svc);
  return body.dump();
}

Service CopyServiceMetadata(const Service &s) {
  Service out;
  out.name = s.name;
  out.inject_env = s.inject_env;
  out.disclosure = s.disclosure;
  out.policy = s.policy;
  out.website_url = s.website_url;
  out.website_host = s.website_host;
  out.company = s.company;
  out.details = s.details;
  out.expires_at = s.expires_at;
  out.created_at = s.created_at;
  out.updated_at = s.updated_at;
  out.update_timestamps = s.update_timestamps;
  return out;
}
absl::Status ValidateService(const Service &s) {
  if (s.name.empty())
    return absl::InvalidArgumentError("service name is required");
  if (s.inject_env.empty())
    return absl::InvalidArgumentError("--inject-env is required");
  if (s.website_url.empty())
    return absl::InvalidArgumentError("--website is required");
  if (s.website_host.empty())
    return absl::InvalidArgumentError("website host is required");
  if (s.company.empty())
    return absl::InvalidArgumentError("--company is required");
  if (s.details.empty())
    return absl::InvalidArgumentError("--details is required");
  if (s.policy.max_ttl_seconds == 0 || s.policy.max_uses == 0)
    return absl::InvalidArgumentError("policy ceilings must be non-zero");
  return absl::OkStatus();
}

} // namespace

absl::Status Vault::Init(const std::string &dir,
                         const std::string &passphrase) {
  if (!EnsureDir(dir))
    return absl::InternalError("cannot create " + dir);
  if (fs::exists(VaultFile(dir)))
    return absl::AlreadyExistsError("vault already exists at " +
                                    VaultFile(dir));

  Vault v;
  v.dir_ = dir;
  auto st = RandomBytes(v.salt_.data(), kSaltBytes);
  if (!st.ok())
    return st;
  auto key = DeriveKey(passphrase, v.salt_.data(), v.kdf_);
  if (!key.ok())
    return key.status();
  v.key_ = std::move(*key);
  return v.Save();
}

absl::StatusOr<Vault> Vault::Open(const std::string &dir,
                                  const std::string &passphrase) {
  auto raw = ReadFile(VaultFile(dir));
  if (!raw.ok())
    return raw.status();

  json head = json::parse(*raw, nullptr, false);
  if (head.is_discarded())
    return absl::DataLossError("vault file is not valid JSON");

  Vault v;
  v.dir_ = dir;
  const auto &kdf = head.at("kdf");
  v.kdf_.nb_blocks = kdf.value("nb_blocks", 65536u);
  v.kdf_.nb_passes = kdf.value("nb_passes", 3u);
  v.kdf_.nb_lanes = kdf.value("nb_lanes", 1u);

  auto salt = FromHex(kdf.at("salt").get<std::string>());
  if (!salt.ok())
    return salt.status();
  if (salt->size() != kSaltBytes)
    return absl::DataLossError("bad salt length");
  std::copy(salt->begin(), salt->end(), v.salt_.begin());

  auto key = DeriveKey(passphrase, v.salt_.data(), v.kdf_);
  if (!key.ok())
    return key.status();
  v.key_ = std::move(*key);

  auto blob = FromHex(head.at("body").get<std::string>());
  if (!blob.ok())
    return blob.status();
  auto plain = AeadOpen(v.key_, blob->data(), blob->size());
  if (!plain.ok())
    return plain.status();

  json body = json::parse(
      std::string(reinterpret_cast<const char *>(plain->data()), plain->size()),
      nullptr, false);
  if (body.is_discarded())
    return absl::DataLossError("decrypted vault body is not JSON");
  if (body.value("schema_version", 0) != kBodySchemaVersion)
    return absl::DataLossError(
        "unsupported vault body schema; recreate the vault with this version");
  if (!body.contains("services") || !body["services"].is_object())
    return absl::DataLossError("vault body schema missing services object");

  try {
    for (auto &[name, j] : body.at("services").items()) {
      Service s;
      s.name = RequiredString(j, "name", name);
      if (s.name != name)
        return absl::DataLossError("service key/name mismatch for '" + name +
                                   "'");
      s.inject_env = RequiredString(j, "inject_env", name);
      auto disc = ParseDisclosure(RequiredString(j, "disclosure", name));
      if (!disc.ok())
        return disc.status();
      s.disclosure = *disc;
      const auto &p = j.at("policy");
      s.policy.max_ttl_seconds = RequiredU32(p, "max_ttl_seconds", name);
      s.policy.max_uses = RequiredU32(p, "max_uses", name);
      s.policy.description = RequiredString(p, "description", name);
      s.policy.guidance = RequiredString(p, "guidance", name);
      s.website_url = RequiredString(j, "website_url", name);
      s.website_host = RequiredString(j, "website_host", name);
      s.company = RequiredString(j, "company", name);
      s.details = RequiredString(j, "details", name);
      s.expires_at = j.value("expires_at", "");
      s.created_at = RequiredString(j, "created_at", name);
      s.updated_at = RequiredString(j, "updated_at", name);
      if (!j.contains("update_timestamps") ||
          !j["update_timestamps"].is_array())
        return absl::DataLossError("service '" + name +
                                   "' missing update_timestamps");
      for (const auto &ts : j["update_timestamps"])
        s.update_timestamps.push_back(ts.get<std::string>());
      std::string cred = RequiredString(j, "credential", name);
      s.credential.assign(cred);
      SecureZero(cred.data(), cred.size());
      auto valid = ValidateService(s);
      if (!valid.ok())
        return valid;
      v.services_.emplace(name, std::move(s));
    }
  } catch (const std::exception &e) {
    return absl::DataLossError(e.what());
  }
  return v;
}

absl::Status Vault::Save() const {
  std::string body = SerializeBody(services_);
  auto blob = AeadSeal(
      key_, reinterpret_cast<const std::uint8_t *>(body.data()), body.size());
  SecureZero(body.data(), body.size());
  if (!blob.ok())
    return blob.status();

  json head;
  head["version"] = 1;
  head["kdf"] = {{"salt", ToHex(salt_.data(), kSaltBytes)},
                 {"nb_blocks", kdf_.nb_blocks},
                 {"nb_passes", kdf_.nb_passes},
                 {"nb_lanes", kdf_.nb_lanes}};
  head["body"] = ToHex(blob->data(), blob->size());
  return WriteFileAtomic(VaultFile(dir_), head.dump(2));
}

absl::Status Vault::AddService(Service service, SecureBuffer credential) {
  auto valid = ValidateService(service);
  if (!valid.ok())
    return valid;
  std::string now = NowIso8601();
  service.created_at = now;
  service.updated_at = now;
  service.update_timestamps.clear();
  service.update_timestamps.push_back(now);
  service.credential = std::move(credential);
  services_[service.name] = std::move(service);
  return Save();
}

absl::Status Vault::EditService(const std::string &name, const Service &updates,
                                const SecureBuffer *credential) {
  auto it = services_.find(name);
  if (it == services_.end())
    return absl::NotFoundError("unknown service '" + name + "'");
  Service edited = CopyServiceMetadata(updates);
  edited.name = name;
  edited.created_at = it->second.created_at;
  edited.update_timestamps = it->second.update_timestamps;
  std::string now = NowIso8601();
  edited.updated_at = now;
  edited.update_timestamps.push_back(now);
  if (credential) {
    edited.credential.assign(reinterpret_cast<const char *>(credential->data()),
                             credential->size());
  } else {
    edited.credential.assign(
        reinterpret_cast<const char *>(it->second.credential.data()),
        it->second.credential.size());
  }
  auto valid = ValidateService(edited);
  if (!valid.ok())
    return valid;
  it->second = std::move(edited);
  return Save();
}

absl::Status Vault::DeleteService(const std::string &name) {
  auto it = services_.find(name);
  if (it == services_.end())
    return absl::NotFoundError("unknown service '" + name + "'");
  services_.erase(it);
  return Save();
}

std::vector<std::string> Vault::ServiceNames() const {
  std::vector<std::string> out;
  out.reserve(services_.size());
  for (const auto &[name, _] : services_)
    out.push_back(name);
  return out;
}

const Service *Vault::Find(const std::string &name) const {
  auto it = services_.find(name);
  return it == services_.end() ? nullptr : &it->second;
}

} // namespace prout

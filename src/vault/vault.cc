#include "vault/vault.h"

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

std::string VaultFile(const std::string &dir) {
  return (fs::path(dir) / "vault.json").string();
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

// Serializes services (including plaintext credentials) to a JSON string that
// the caller must wipe after encrypting.
std::string SerializeBody(const std::map<std::string, Service> &services) {
  json body;
  json svc = json::object();
  for (const auto &[name, s] : services) {
    json j;
    j["env_var"] = s.env_var;
    j["disclosure"] = DisclosureName(s.disclosure);
    j["policy"] = {{"max_ttl_seconds", s.policy.max_ttl_seconds},
                   {"max_uses", s.policy.max_uses},
                   {"description", s.policy.description},
                   {"guidance", s.policy.guidance}};
    j["credential"] =
        std::string(reinterpret_cast<const char *>(s.credential.data()),
                    s.credential.size());
    svc[name] = std::move(j);
  }
  body["services"] = std::move(svc);
  return body.dump();
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

  if (body.contains("services")) {
    for (auto &[name, j] : body.at("services").items()) {
      Service s;
      s.name = name;
      s.env_var = j.value("env_var", "");
      auto disc = ParseDisclosure(j.value("disclosure", "inject"));
      if (!disc.ok())
        return disc.status();
      s.disclosure = *disc;
      const auto &p = j.at("policy");
      s.policy.max_ttl_seconds = p.value("max_ttl_seconds", 900u);
      s.policy.max_uses = p.value("max_uses", 3u);
      s.policy.description = p.value("description", "");
      s.policy.guidance = p.value("guidance", "");
      std::string cred = j.value("credential", "");
      s.credential.assign(cred);
      SecureZero(cred.data(), cred.size());
      v.services_.emplace(name, std::move(s));
    }
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

absl::Status Vault::AddService(const std::string &name,
                               const std::string &env_var,
                               Disclosure disclosure, const Policy &policy,
                               SecureBuffer credential) {
  Service s;
  s.name = name;
  s.env_var = env_var;
  s.disclosure = disclosure;
  s.policy = policy;
  s.credential = std::move(credential);
  services_[name] = std::move(s);
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

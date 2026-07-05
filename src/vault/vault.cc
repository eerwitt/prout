#include "vault/vault.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
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
constexpr int kLogSchemaVersion = 1;
constexpr int kPayloadSchemaVersion = 1;

struct Mutation {
  std::string revision_id;
  std::string machine;
  std::string ts;
  std::uint64_t seq = 0;
  std::string action;
  std::string service;
  std::map<std::string, std::string> fields;
  SecureBuffer credential;
  bool has_credential = false;
};

struct FieldRevision {
  std::string value;
  std::string revision_id;
  std::string machine;
  std::string ts;
  std::string sort_key;
};

struct ServiceReplay {
  std::string name;
  std::string add_key;
  std::string delete_key;
  std::map<std::string, FieldRevision> fields;
  SecureBuffer credential;
  std::string credential_sort_key;
  bool has_credential = false;
  std::vector<std::string> update_timestamps;
};

struct ReplayedVault {
  std::map<std::string, Service> services;
  std::vector<VaultHistoryEntry> history;
};

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

std::string MachineVaultFile(const std::string &dir,
                             const std::string &machine) {
  return (fs::path(dir) / ("vault-" + machine + ".jsonl")).string();
}

std::string RevisionId(const std::string &machine, const std::string &ts) {
  std::uint8_t bytes[16]{};
  if (!RandomBytes(bytes, sizeof(bytes)).ok())
    return machine + "-" + ts + "-random-failed";
  return machine + "-" + ts + "-" + ToHex(bytes, sizeof(bytes));
}

std::string SortKey(const Mutation &m) {
  char seq[32];
  std::snprintf(seq, sizeof(seq), "%020llu",
                static_cast<unsigned long long>(m.seq));
  return m.ts + "|" + m.machine + "|" + seq + "|" + m.revision_id;
}

std::string Canonical(const nlohmann::ordered_json &rec) {
  nlohmann::ordered_json copy = rec;
  copy.erase("hash");
  return copy.dump();
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

std::map<std::string, std::string> ServiceFields(const Service &s) {
  return {{"inject_env", s.inject_env},
          {"disclosure", DisclosureName(s.disclosure)},
          {"policy.max_ttl_seconds", std::to_string(s.policy.max_ttl_seconds)},
          {"policy.max_uses", std::to_string(s.policy.max_uses)},
          {"policy.description", s.policy.description},
          {"policy.guidance", s.policy.guidance},
          {"website_url", s.website_url},
          {"website_host", s.website_host},
          {"company", s.company},
          {"details", s.details},
          {"expires_at", s.expires_at}};
}

std::uint32_t ParseStoredU32(const std::string &s, const std::string &field,
                             const std::string &service) {
  char *end = nullptr;
  unsigned long v = std::strtoul(s.c_str(), &end, 10);
  if (end == s.c_str() || *end != '\0')
    throw std::runtime_error("service '" + service + "' has bad " + field);
  return static_cast<std::uint32_t>(v);
}

std::string RequiredField(const ServiceReplay &r, const std::string &field) {
  auto it = r.fields.find(field);
  if (it == r.fields.end())
    throw std::runtime_error("service '" + r.name + "' missing " + field);
  return it->second.value;
}

absl::StatusOr<Service> BuildService(const ServiceReplay &r) {
  try {
    Service s;
    s.name = r.name;
    s.inject_env = RequiredField(r, "inject_env");
    auto disc = ParseDisclosure(RequiredField(r, "disclosure"));
    if (!disc.ok())
      return disc.status();
    s.disclosure = *disc;
    s.policy.max_ttl_seconds =
        ParseStoredU32(RequiredField(r, "policy.max_ttl_seconds"),
                       "policy.max_ttl_seconds", r.name);
    s.policy.max_uses = ParseStoredU32(RequiredField(r, "policy.max_uses"),
                                       "policy.max_uses", r.name);
    s.policy.description = RequiredField(r, "policy.description");
    s.policy.guidance = RequiredField(r, "policy.guidance");
    s.website_url = RequiredField(r, "website_url");
    s.website_host = RequiredField(r, "website_host");
    s.company = RequiredField(r, "company");
    s.details = RequiredField(r, "details");
    s.expires_at = RequiredField(r, "expires_at");
    s.created_at = r.add_key.substr(0, r.add_key.find('|'));
    s.updated_at =
        r.update_timestamps.empty() ? s.created_at : r.update_timestamps.back();
    s.update_timestamps = r.update_timestamps;
    s.credential.assign(r.credential.data(), r.credential.size());
    auto valid = ValidateService(s);
    if (!valid.ok())
      return valid;
    return s;
  } catch (const std::exception &e) {
    return absl::DataLossError(e.what());
  }
}

std::vector<std::string> VaultLogPaths(const std::string &dir) {
  std::vector<std::string> paths;
  std::error_code ec;
  if (!fs::exists(dir, ec))
    return paths;
  for (const auto &entry : fs::directory_iterator(dir, ec)) {
    if (ec)
      break;
    if (!entry.is_regular_file())
      continue;
    std::string name = entry.path().filename().string();
    if (name.rfind("vault-", 0) == 0 && entry.path().extension() == ".jsonl")
      paths.push_back(entry.path().string());
  }
  std::sort(paths.begin(), paths.end());
  return paths;
}

absl::Status ReadKdfFromHeader(const nlohmann::ordered_json &j, KdfParams *kdf,
                               std::array<std::uint8_t, kSaltBytes> *salt) {
  if (!j.contains("kdf") || !j["kdf"].is_object())
    return absl::DataLossError("vault header missing kdf");
  const auto &jkdf = j["kdf"];
  kdf->nb_blocks = jkdf.value("nb_blocks", 65536u);
  kdf->nb_passes = jkdf.value("nb_passes", 3u);
  kdf->nb_lanes = jkdf.value("nb_lanes", 1u);
  auto raw_salt = FromHex(jkdf.at("salt").get<std::string>());
  if (!raw_salt.ok())
    return raw_salt.status();
  if (raw_salt->size() != kSaltBytes)
    return absl::DataLossError("bad salt length");
  std::copy(raw_salt->begin(), raw_salt->end(), salt->begin());
  return absl::OkStatus();
}

absl::Status VerifyOneLog(const std::string &path, KdfParams *kdf,
                          std::array<std::uint8_t, kSaltBytes> *salt,
                          bool *have_kdf,
                          std::vector<nlohmann::ordered_json> *records) {
  std::ifstream f(path);
  if (!f)
    return absl::InternalError("cannot open " + path);
  std::string line;
  std::string prev = "GENESIS";
  int lineno = 0;
  bool saw_header = false;
  while (std::getline(f, line)) {
    if (line.empty())
      continue;
    ++lineno;
    nlohmann::ordered_json j =
        nlohmann::ordered_json::parse(line, nullptr, false);
    if (j.is_discarded())
      return absl::DataLossError(path + ": record " + std::to_string(lineno) +
                                 " is not valid JSON");
    if (j.value("prev_hash", "") != prev)
      return absl::DataLossError(path + ": chain break at record " +
                                 std::to_string(lineno));
    std::string want = Blake2bHex(prev, Canonical(j));
    if (j.value("hash", "") != want)
      return absl::DataLossError(path + ": tampered record at line " +
                                 std::to_string(lineno));
    if (lineno == 1) {
      if (j.value("type", "") != "header")
        return absl::DataLossError(path + ": first record is not a header");
      KdfParams parsed_kdf;
      std::array<std::uint8_t, kSaltBytes> parsed_salt{};
      auto st = ReadKdfFromHeader(j, &parsed_kdf, &parsed_salt);
      if (!st.ok())
        return st;
      if (*have_kdf) {
        if (parsed_kdf.nb_blocks != kdf->nb_blocks ||
            parsed_kdf.nb_passes != kdf->nb_passes ||
            parsed_kdf.nb_lanes != kdf->nb_lanes ||
            !std::equal(parsed_salt.begin(), parsed_salt.end(),
                        salt->begin())) {
          return absl::DataLossError(path + ": vault header does not match");
        }
      } else {
        *kdf = parsed_kdf;
        *salt = parsed_salt;
      }
      *have_kdf = true;
      saw_header = true;
    } else if (j.value("type", "") == "header") {
      return absl::DataLossError(path + ": duplicate header");
    }
    prev = j.value("hash", "");
    records->push_back(std::move(j));
  }
  if (!saw_header)
    return absl::DataLossError(path + ": empty vault log");
  return absl::OkStatus();
}

absl::StatusOr<Mutation> DecryptMutation(const SecureBuffer &key,
                                         const nlohmann::ordered_json &rec) {
  Mutation m;
  m.machine = rec.value("machine", "");
  m.ts = rec.value("ts", "");
  m.seq = rec.value("seq", 0ull);
  auto blob = FromHex(rec.at("payload").get<std::string>());
  if (!blob.ok())
    return blob.status();
  auto plain = AeadOpen(key, blob->data(), blob->size());
  if (!plain.ok())
    return plain.status();
  std::string raw(reinterpret_cast<const char *>(plain->data()), plain->size());
  json payload = json::parse(raw, nullptr, false);
  SecureZero(raw.data(), raw.size());
  if (payload.is_discarded())
    return absl::DataLossError("vault mutation payload is not JSON");
  if (payload.value("schema_version", 0) != kPayloadSchemaVersion)
    return absl::DataLossError("unsupported vault mutation schema");
  m.revision_id = payload.at("revision_id").get<std::string>();
  m.machine = payload.value("machine", m.machine);
  m.ts = payload.value("ts", m.ts);
  m.action = payload.at("action").get<std::string>();
  m.service = payload.at("service").get<std::string>();
  if (payload.contains("fields")) {
    for (const auto &[k, v] : payload["fields"].items())
      m.fields[k] = v.get<std::string>();
  }
  if (payload.contains("credential_hex")) {
    auto cred = FromHex(payload["credential_hex"].get<std::string>());
    if (!cred.ok())
      return cred.status();
    m.credential.assign(cred->data(), cred->size());
    SecureZero(cred->data(), cred->size());
    m.has_credential = true;
  }
  return m;
}

absl::StatusOr<std::vector<Mutation>>
ReadMutations(const std::string &dir, const SecureBuffer &key, KdfParams *kdf,
              std::array<std::uint8_t, kSaltBytes> *salt) {
  auto paths = VaultLogPaths(dir);
  if (paths.empty())
    return absl::NotFoundError("vault is not initialized in " + dir);
  bool have_kdf = false;
  std::vector<nlohmann::ordered_json> records;
  for (const auto &path : paths) {
    auto st = VerifyOneLog(path, kdf, salt, &have_kdf, &records);
    if (!st.ok())
      return st;
  }
  std::vector<Mutation> out;
  for (const auto &rec : records) {
    if (rec.value("type", "") != "mutation")
      continue;
    auto m = DecryptMutation(key, rec);
    if (!m.ok())
      return m.status();
    out.push_back(std::move(*m));
  }
  return out;
}

absl::Status AppendHeader(const std::string &dir, const KdfParams &kdf,
                          const std::array<std::uint8_t, kSaltBytes> &salt) {
  nlohmann::ordered_json rec;
  rec["schema_version"] = kLogSchemaVersion;
  rec["type"] = "header";
  rec["ts"] = NowIso8601();
  rec["machine"] = MachineId();
  rec["kdf"] = {{"salt", ToHex(salt.data(), salt.size())},
                {"nb_blocks", kdf.nb_blocks},
                {"nb_passes", kdf.nb_passes},
                {"nb_lanes", kdf.nb_lanes}};
  rec["prev_hash"] = "GENESIS";
  rec["hash"] = Blake2bHex("GENESIS", Canonical(rec));
  std::ofstream f(MachineVaultFile(dir, MachineId()), std::ios::app);
  if (!f)
    return absl::InternalError("cannot write vault log");
  f << rec.dump() << "\n";
  if (!f)
    return absl::InternalError("vault header write failed");
  return absl::OkStatus();
}

absl::Status AppendMutation(const std::string &dir, const SecureBuffer &key,
                            const KdfParams &kdf,
                            const std::array<std::uint8_t, kSaltBytes> &salt,
                            Mutation m) {
  if (!EnsureDir(dir))
    return absl::InternalError("cannot create " + dir);
  const std::string path = MachineVaultFile(dir, MachineId());
  if (!fs::exists(path)) {
    auto st = AppendHeader(dir, kdf, salt);
    if (!st.ok())
      return st;
  }

  std::string prev = "GENESIS";
  std::uint64_t seq = 0;
  {
    std::ifstream f(path);
    std::string line, last;
    while (std::getline(f, line)) {
      if (!line.empty()) {
        last = line;
        ++seq;
      }
    }
    if (!last.empty()) {
      json j = json::parse(last, nullptr, false);
      if (!j.is_discarded() && j.contains("hash"))
        prev = j["hash"].get<std::string>();
    }
  }

  json payload;
  payload["schema_version"] = kPayloadSchemaVersion;
  payload["revision_id"] = m.revision_id;
  payload["machine"] = m.machine;
  payload["ts"] = m.ts;
  payload["action"] = m.action;
  payload["service"] = m.service;
  payload["fields"] = m.fields;
  if (m.has_credential) {
    payload["credential_hex"] = ToHex(m.credential.data(), m.credential.size());
  }
  std::string plain = payload.dump();
  auto blob = AeadSeal(
      key, reinterpret_cast<const std::uint8_t *>(plain.data()), plain.size());
  SecureZero(plain.data(), plain.size());
  if (!blob.ok())
    return blob.status();

  nlohmann::ordered_json rec;
  rec["schema_version"] = kLogSchemaVersion;
  rec["type"] = "mutation";
  rec["ts"] = m.ts;
  rec["machine"] = m.machine;
  rec["seq"] = seq;
  rec["payload"] = ToHex(blob->data(), blob->size());
  rec["prev_hash"] = prev;
  rec["hash"] = Blake2bHex(prev, Canonical(rec));
  SecureZero(blob->data(), blob->size());

  std::ofstream f(path, std::ios::app);
  if (!f)
    return absl::InternalError("cannot append to " + path);
  f << rec.dump() << "\n";
  if (!f)
    return absl::InternalError("vault append write failed");
  return absl::OkStatus();
}

void ApplyRevision(ServiceReplay *r, const Mutation &m) {
  const std::string key = SortKey(m);
  if (m.action == "add") {
    if (key > r->add_key) {
      r->add_key = key;
      r->fields.clear();
      r->has_credential = false;
      r->update_timestamps.clear();
    }
  } else if (m.action == "delete") {
    if (key > r->delete_key)
      r->delete_key = key;
    return;
  }

  if (r->add_key.empty() || key < r->add_key || key <= r->delete_key)
    return;
  for (const auto &[field, value] : m.fields) {
    auto it = r->fields.find(field);
    if (it == r->fields.end() || key > it->second.sort_key) {
      r->fields[field] = FieldRevision{.value = value,
                                       .revision_id = m.revision_id,
                                       .machine = m.machine,
                                       .ts = m.ts,
                                       .sort_key = key};
    }
  }
  if (m.has_credential &&
      (!r->has_credential || key > r->credential_sort_key)) {
    r->credential.assign(m.credential.data(), m.credential.size());
    r->credential_sort_key = key;
    r->has_credential = true;
  }
  r->update_timestamps.push_back(m.ts);
}

bool MutationActive(const std::map<std::string, ServiceReplay> &states,
                    const Mutation &m) {
  auto it = states.find(m.service);
  if (it == states.end())
    return false;
  const ServiceReplay &r = it->second;
  const std::string key = SortKey(m);
  if (m.action == "delete")
    return key == r.delete_key && key > r.add_key;
  if (key <= r.delete_key || key < r.add_key)
    return false;
  if (m.action == "add")
    return key == r.add_key;
  if (m.action == "rotate")
    return r.has_credential && key == r.credential_sort_key;
  for (const auto &[field, _] : m.fields) {
    auto fit = r.fields.find(field);
    if (fit != r.fields.end() && fit->second.sort_key == key)
      return true;
  }
  return false;
}

absl::StatusOr<ReplayedVault> Replay(std::vector<Mutation> mutations) {
  ReplayedVault out;
  std::sort(mutations.begin(), mutations.end(),
            [](const Mutation &a, const Mutation &b) {
              return SortKey(a) < SortKey(b);
            });
  std::map<std::string, ServiceReplay> states;
  for (const Mutation &m : mutations) {
    auto &state = states[m.service];
    state.name = m.service;
    ApplyRevision(&state, m);
  }

  for (const auto &[name, state] : states) {
    if (state.add_key.empty() || state.delete_key > state.add_key ||
        !state.has_credential)
      continue;
    auto svc = BuildService(state);
    if (!svc.ok())
      return svc.status();
    out.services.emplace(name, std::move(*svc));
  }

  for (const Mutation &m : mutations) {
    VaultHistoryEntry h;
    h.revision_id = m.revision_id;
    h.machine = m.machine;
    h.timestamp = m.ts;
    h.action = m.action;
    h.service = m.service;
    for (const auto &[field, _] : m.fields)
      h.fields.push_back(field);
    if (m.has_credential)
      h.fields.push_back("credential");
    h.active = MutationActive(states, m);
    out.history.push_back(std::move(h));
  }
  return out;
}

} // namespace

absl::StatusOr<Vault> OpenInternal(const std::string &dir,
                                   const std::string &passphrase, bool replay) {
  auto paths = VaultLogPaths(dir);
  if (paths.empty())
    return absl::NotFoundError("vault is not initialized in " + dir);

  Vault v;
  v.dir_ = dir;
  bool have_kdf = false;
  std::vector<nlohmann::ordered_json> unused;
  for (const auto &path : paths) {
    auto st = VerifyOneLog(path, &v.kdf_, &v.salt_, &have_kdf, &unused);
    if (!st.ok())
      return st;
  }
  if (!have_kdf)
    return absl::DataLossError("vault logs missing kdf header");

  auto key = DeriveKey(passphrase, v.salt_.data(), v.kdf_);
  if (!key.ok())
    return key.status();
  v.key_ = std::move(*key);

  auto mutations = ReadMutations(dir, v.key_, &v.kdf_, &v.salt_);
  if (!mutations.ok())
    return mutations.status();
  if (replay) {
    auto replayed = Replay(std::move(*mutations));
    if (!replayed.ok())
      return replayed.status();
    v.services_ = std::move(replayed->services);
    v.history_ = std::move(replayed->history);
  }
  return v;
}

absl::Status Vault::Init(const std::string &dir,
                         const std::string &passphrase) {
  if (!EnsureDir(dir))
    return absl::InternalError("cannot create " + dir);
  if (!VaultLogPaths(dir).empty())
    return absl::AlreadyExistsError("vault already exists in " + dir);

  Vault v;
  v.dir_ = dir;
  auto st = RandomBytes(v.salt_.data(), kSaltBytes);
  if (!st.ok())
    return st;
  auto key = DeriveKey(passphrase, v.salt_.data(), v.kdf_);
  if (!key.ok())
    return key.status();
  v.key_ = std::move(*key);
  return AppendHeader(dir, v.kdf_, v.salt_);
}

absl::StatusOr<Vault> Vault::Open(const std::string &dir,
                                  const std::string &passphrase) {
  return OpenInternal(dir, passphrase, true);
}

absl::Status Vault::Verify(const std::string &dir,
                           const std::string &passphrase) {
  auto vault = OpenInternal(dir, passphrase, false);
  return vault.ok() ? absl::OkStatus() : vault.status();
}

absl::Status Vault::AddService(Service service, SecureBuffer credential) {
  auto valid = ValidateService(service);
  if (!valid.ok())
    return valid;
  if (services_.find(service.name) != services_.end())
    return absl::AlreadyExistsError("service already exists '" + service.name +
                                    "'");
  std::string now = NowIso8601();
  service.credential.assign(credential.data(), credential.size());
  Mutation m;
  m.revision_id = RevisionId(MachineId(), now);
  m.machine = MachineId();
  m.ts = now;
  m.action = "add";
  m.service = service.name;
  m.fields = ServiceFields(service);
  m.credential = std::move(credential);
  m.has_credential = true;
  auto st = AppendMutation(dir_, key_, kdf_, salt_, std::move(m));
  if (!st.ok())
    return st;
  service.created_at = now;
  service.updated_at = now;
  service.update_timestamps = {now};
  services_.emplace(service.name, std::move(service));
  return absl::OkStatus();
}

absl::Status Vault::EditService(const std::string &name,
                                const Service &updates) {
  auto it = services_.find(name);
  if (it == services_.end())
    return absl::NotFoundError("unknown service '" + name + "'");
  auto valid = ValidateService(updates);
  if (!valid.ok())
    return valid;
  std::map<std::string, std::string> before = ServiceFields(it->second);
  std::map<std::string, std::string> after = ServiceFields(updates);
  std::map<std::string, std::string> changed;
  for (const auto &[field, value] : after) {
    if (before[field] != value)
      changed[field] = value;
  }
  if (changed.empty())
    return absl::OkStatus();

  std::string now = NowIso8601();
  Mutation m;
  m.revision_id = RevisionId(MachineId(), now);
  m.machine = MachineId();
  m.ts = now;
  m.action = "edit";
  m.service = name;
  m.fields = std::move(changed);
  return AppendMutation(dir_, key_, kdf_, salt_, std::move(m));
}

absl::Status Vault::RotateService(const std::string &name,
                                  SecureBuffer credential) {
  if (services_.find(name) == services_.end())
    return absl::NotFoundError("unknown service '" + name + "'");
  std::string now = NowIso8601();
  Mutation m;
  m.revision_id = RevisionId(MachineId(), now);
  m.machine = MachineId();
  m.ts = now;
  m.action = "rotate";
  m.service = name;
  m.credential = std::move(credential);
  m.has_credential = true;
  return AppendMutation(dir_, key_, kdf_, salt_, std::move(m));
}

absl::Status Vault::DeleteService(const std::string &name) {
  if (services_.find(name) == services_.end())
    return absl::NotFoundError("unknown service '" + name + "'");
  std::string now = NowIso8601();
  Mutation m;
  m.revision_id = RevisionId(MachineId(), now);
  m.machine = MachineId();
  m.ts = now;
  m.action = "delete";
  m.service = name;
  return AppendMutation(dir_, key_, kdf_, salt_, std::move(m));
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

std::vector<VaultHistoryEntry> Vault::History(const std::string &name) const {
  std::vector<VaultHistoryEntry> out;
  for (const auto &h : history_) {
    if (h.service == name)
      out.push_back(h);
  }
  return out;
}

} // namespace prout

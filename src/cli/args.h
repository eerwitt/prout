// Tiny argument parser: `--flag value` pairs plus a trailing command after a
// bare `--`. Header-only; shared by the client subcommands.
#pragma once

#include <map>
#include <string>
#include <vector>

namespace prout {

struct Args {
  std::map<std::string, std::string> flags;
  std::vector<std::string> positional;
  std::vector<std::string> command; // everything after a bare "--"
  bool has_dashdash = false;

  std::string Get(const std::string &key, const std::string &def = "") const {
    auto it = flags.find(key);
    return it == flags.end() ? def : it->second;
  }
  bool Has(const std::string &key) const { return flags.count(key) > 0; }
};

inline Args ParseArgs(const std::vector<std::string> &in) {
  Args a;
  std::size_t i = 0;
  for (; i < in.size(); ++i) {
    const std::string &t = in[i];
    if (t == "--") {
      a.has_dashdash = true;
      for (std::size_t j = i + 1; j < in.size(); ++j)
        a.command.push_back(in[j]);
      break;
    }
    if (t.rfind("--", 0) == 0) {
      std::string key = t.substr(2);
      auto eq = key.find('=');
      if (eq != std::string::npos) {
        a.flags[key.substr(0, eq)] = key.substr(eq + 1);
      } else if (i + 1 < in.size() && in[i + 1].rfind("--", 0) != 0 &&
                 in[i + 1] != "--") {
        a.flags[key] = in[++i];
      } else {
        a.flags[key] = ""; // bare boolean flag
      }
    } else {
      a.positional.push_back(t);
    }
  }
  return a;
}

} // namespace prout

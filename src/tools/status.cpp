// SPDX-License-Identifier: GPL-2.0
#include "status.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <zlib.h>

#include "common.hpp"

namespace uidfake {
namespace {

/* Where this binary was started from: the module directory, the way the boot
 * scripts invoke it. */
std::filesystem::path module_dir() {
  std::error_code ec;
  const auto self = std::filesystem::read_symlink("/proc/self/exe", ec);

  if (ec || self.empty())
    return {};
  return self.parent_path();
}

/* The description without the status this tool put in front of it earlier. */
std::string strip_status(const std::string &line) {
  if (line.empty() || line[0] != '[')
    return line;
  const auto close = line.find("] ");

  if (close == std::string::npos)
    return line;
  return line.substr(close + 2);
}

/* One config line's value, or empty. */
std::optional<unsigned int> config_value(const std::string &text,
                                         std::string_view key) {
  const std::string prefix = std::string(key) + "=";

  for (std::size_t at = text.find(prefix); at != std::string::npos;
       at = text.find(prefix, at + 1)) {
    if (at != 0 && text[at - 1] != '\n')
      continue;
    const std::size_t begin = at + prefix.size();
    const std::size_t end = text.find('\n', begin);
    const std::string value = text.substr(begin, end - begin);
    if (!value.empty() &&
        value.find_first_not_of("0123456789") == std::string::npos)
      return static_cast<unsigned int>(std::stoul(value));
  }
  return std::nullopt;
}

} // namespace

DeviceGeometry read_device_config() {
  /* The config does not change while the kernel runs: read it once. */
  static const DeviceGeometry cached = [] {
    DeviceGeometry out;
    gzFile file = gzopen("/proc/config.gz", "rb");
    if (file == nullptr)
      return out;

    std::string text;
    char buffer[16384];
    int got;
    while ((got = gzread(file, buffer,
                         static_cast<unsigned int>(sizeof(buffer)))) > 0)
      text.append(buffer, static_cast<std::size_t>(got));
    gzclose(file);
    if (text.empty())
      return out;

    out.va_bits = config_value(text, "CONFIG_ARM64_VA_BITS");
    if (text.find("CONFIG_ARM64_4K_PAGES=y") != std::string::npos)
      out.page_shift = 12;
    else if (text.find("CONFIG_ARM64_16K_PAGES=y") != std::string::npos)
      out.page_shift = 14;
    else if (text.find("CONFIG_ARM64_64K_PAGES=y") != std::string::npos)
      out.page_shift = 16;
    return out;
  }();
  return cached;
}

void report_status(std::string_view text) {
  static std::string last;
  const std::string wanted(text);

  if (wanted == last)
    return; /* the line would not change */

  const auto dir = module_dir();
  if (dir.empty())
    return;

  const auto prop = dir / "module.prop";
  std::ifstream in(prop);
  if (!in)
    return;

  std::vector<std::string> lines;
  std::string line;
  bool touched = false;

  while (std::getline(in, line)) {
    if (line.rfind("description=", 0) == 0) {
      const auto rest = strip_status(line.substr(12));
      std::string rebuilt = "description=";
      if (!wanted.empty()) {
        rebuilt += '[';
        rebuilt += wanted;
        rebuilt += "] ";
      }
      line = rebuilt + rest;
      touched = true;
    }
    lines.push_back(line);
  }
  in.close();
  if (!touched)
    return;

  const auto tmp = dir / "module.prop.tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out)
      return;
    for (const auto &l : lines)
      out << l << "\n";
  }
  std::error_code ec;
  std::filesystem::rename(tmp, prop, ec);
  if (ec) {
    Log::warn("could not update {}: {}", prop.string(), ec.message());
    return;
  }
  last = wanted;
}

} // namespace uidfake

// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>

#include "common.hpp"
#include "packages.hpp"
#include "paths.hpp"

namespace uidfake {
using Presets =
    std::map<std::string, std::set<std::string, std::less<>>, std::less<>>;

/* preset_rules.cpp: the scanned half of the OSS presets, computed from the
 * installed packages so the tool does not depend on the app's per-process copy.
 */
/* What one package is, for the rules below. */
struct ScanTarget {
  std::uint32_t uid = 0;
  std::filesystem::path code_dir;
  bool system = false;
};

using ScanMap = std::map<std::string, ScanTarget, std::less<>>;

[[nodiscard]] Presets
scan_presets(const ScanMap &apps,
             const std::set<std::string, std::less<>> &wanted);

/* The same rules, reading the package list from the package manager's database.
 */
[[nodiscard]] Presets
scan_presets(const PackageDb &packages,
             const std::set<std::string, std::less<>> &wanted);

/*
 * The rules of one config file. The two apps share their code and not their
 * config format, so each has its own class, and where the file is kept says
 * which one reads it.
 *
 *   HmaRules      HMA builds a hidden set per caller from the extra list and
 * the applied templates, keeps its own list of known packages (xj.a) out of it
 * -- or in, when the caller hides everything else, so they stay visible there
 * -- and useWhitelist turns that set into the visible one: defpackage/m10.java
 * in the app.
 *
 *   HmaOssRules   HMA-OSS has a reserved list of its own
 *                 (Constants.packagesShouldNotHide, which shares no entry with
 *                 HMA's xj.a), added an opposite list and presets, and decides
 *                 pair by pair in a fixed order: HMAService.shouldHide().
 *
 * Both read the config once and answer from it: the parsed config is a map of
 * maps, so a caller's entry is a lookup in it and a caller's lists are arrays
 * in it -- nothing is built beside it. A device has a thousand packages and
 * every one of them is asked about, so nothing here may parse.
 */
/* HMA-OSS reads three things besides the config: the packages its preset cache
 * says are connected to GMS, and the WebView and browser webViewProtection
 * keeps visible. The tool fills them; the tests leave them empty. */
struct PresetFacts {
  std::set<std::string, std::less<>> gms_connected;
  std::string webview;
  std::string browser;

  /* The presets' scanned half, computed from the installed packages by this
   * tool: HMA-OSS rebuilds it per process from a view its own hooks filter, so
   * the app itself is not a reliable source for it. */
  Presets scanned;
};

/* Read HMA-OSS's exported preset membership beside its config file. */
[[nodiscard]] Presets
load_preset_cache(const std::filesystem::path &config_file, PresetFacts &facts);

class Rules {
public:
  virtual ~Rules() = default;

  /* Every (caller, target) pair the kernel should know about. */
  [[nodiscard]] virtual Pairs expand(const PackageDb &packages,
                                     const Presets &presets) const = 0;

  /* One decision. `target_is_system` is what the package manager recorded. */
  [[nodiscard]] virtual bool hides(std::string_view caller,
                                   std::string_view target,
                                   bool target_is_system,
                                   const Presets &presets) const = 0;

  /* Only HMA-OSS has presets, so only it needs the cache read for it. */
  [[nodiscard]] virtual bool uses_presets() const { return false; }

  /* The preset names the config applies, each once. Empty when the format has
   * none, and used to decide whether the cache already answers everything. */
  [[nodiscard]] virtual std::vector<std::string> presets_in_use() const {
    return {};
  }

  /* Facts the decision needs that do not live in the config file. */
  virtual void set_preset_facts(const PresetFacts &facts) { (void)facts; }

  [[nodiscard]] Tool tool() const { return tool_; }
  [[nodiscard]] const std::filesystem::path &path() const { return path_; }

protected:
  /* Reads a config; nullopt when it is not there or does not parse. */
  [[nodiscard]] static std::optional<nlohmann::json>
  read_json(const std::filesystem::path &path);

  Rules(Tool tool, nlohmann::json config, std::filesystem::path path);

  /* The caller's entry in `scope`, or nullptr. */
  [[nodiscard]] const nlohmann::json *
  caller_entry(std::string_view caller) const;

public:
  /* Probe-only: the entry as the tool itself sees it. */
  [[nodiscard]] const nlohmann::json *
  caller_entry_for_probe(std::string_view caller) const {
    return caller_entry(caller);
  }

protected:
  /* The template of that name, or nullptr. */
  [[nodiscard]] const nlohmann::json *
  template_entry(std::string_view name) const;

  /* The array under `key` in `entry`, or nullptr. */
  [[nodiscard]] static const nlohmann::json *
  find_array(const nlohmann::json &entry, std::string_view key);

  /* True when `name` is one of the strings in `array`. A scan on purpose: these
   * are the app's own lists and they are short. */
  [[nodiscard]] static bool in_list(const nlohmann::json &array,
                                    std::string_view name);

  /* The targets of one caller, from a decision that has to be cheap per target.
   */
  template <typename Decides>
  void append_pairs(Pairs &pairs, const PackageDb &packages,
                    std::string_view caller, Decides decides) const {
    const auto caller_uid = packages.uid_of(caller);
    if (!caller_uid || *caller_uid < kFirstAppUid)
      return;
    for (const auto &[target, info] : packages.by_name()) {
      if (target == caller || info.uid < kFirstAppUid)
        continue;
      if (!decides(target, info.uid, packages.is_system(target)))
        continue;
      pairs.push_back(Pair{.caller = *caller_uid, .target = info.uid});
    }
  }

  void log_summary(std::size_t callers, const Pairs &pairs) const;

  nlohmann::json config_;
  std::filesystem::path path_;
  Tool tool_;
  const nlohmann::json *scope_ = nullptr; /* both point into config_ */
  const nlohmann::json *templates_ = nullptr;
};

/* HMA's format, and the list of packages it always knows about (xj.a). */
class HmaRules final : public Rules {
public:
  [[nodiscard]] static std::unique_ptr<HmaRules>
  load(const std::filesystem::path &path);

  HmaRules(nlohmann::json config, std::filesystem::path path)
      : Rules(Tool::Hma, std::move(config), std::move(path)) {}

  [[nodiscard]] Pairs expand(const PackageDb &packages,
                             const Presets &presets) const override;
  [[nodiscard]] bool hides(std::string_view caller, std::string_view target,
                           bool target_is_system,
                           const Presets &presets) const override;

private:
  /* Is the target on this caller's list -- its extra list plus the appList of
   * every template it applies? */
  [[nodiscard]] bool on_list(const nlohmann::json &entry,
                             std::string_view target) const;

  /* The decision for one pair, from an entry that was already looked up. */
  [[nodiscard]] bool hides_target(const nlohmann::json &entry,
                                  std::string_view target,
                                  bool target_is_system) const;
};

/* HMA-OSS's format. */
class HmaOssRules final : public Rules {
public:
  [[nodiscard]] static std::unique_ptr<HmaOssRules>
  load(const std::filesystem::path &path);

  HmaOssRules(nlohmann::json config, std::filesystem::path path);

  [[nodiscard]] Pairs expand(const PackageDb &packages,
                             const Presets &presets) const override;
  [[nodiscard]] bool hides(std::string_view caller, std::string_view target,
                           bool target_is_system,
                           const Presets &presets) const override;
  [[nodiscard]] bool uses_presets() const override { return true; }
  [[nodiscard]] std::vector<std::string> presets_in_use() const override;
  void set_preset_facts(const PresetFacts &facts) override { facts_ = facts; }

  /* What one caller's entry was read as, for the log. */
  [[nodiscard]] std::string describe(const nlohmann::json &entry,
                                     const Presets &presets) const;

  /* What the presets in use added, and which of them the cache did not have:
   * a log line alone then answers "did the presets reach the policy?". */
  void report_presets(const PackageDb &packages, const Presets &presets,
                      const Pairs &pairs) const;

private:
  [[nodiscard]] bool hides_target(std::string_view caller,
                                  const nlohmann::json &entry,
                                  std::string_view target,
                                  bool target_is_system,
                                  const Presets &presets) const;
  [[nodiscard]] bool presets_skip(std::string_view target) const;

  /* True when HMA-OSS would leave the target alone for this caller because the
   * target is connected to GMS and the caller asks as the Play Store. */
  [[nodiscard]] bool gms_ignored(std::string_view caller,
                                 std::string_view target) const;

  /* The packages its presets must leave alone, read once while it is built. */
  std::set<std::string, std::less<>> presets_skip_;
  PresetFacts facts_;
};

} // namespace uidfake

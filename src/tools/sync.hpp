// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "netlink.hpp"
#include "packages.hpp"
#include "paths.hpp"
#include "rules.hpp"
#include "watcher.hpp"

namespace uidfake {

/* Command line. The rule places and the package database are not options: this
 * reads where the tools and the package manager keep them. */
struct Config {
  bool once = false;

  /* --explain CALLER TARGET: print one decision and stop. */
  std::optional<std::pair<std::string, std::string>> explain;

  /* --list CALLER: print every target that caller hides. */
  std::optional<std::string> list;

  /* --template CALLER: print the preset union as a template; with
   * --write-config, put it into the config as well. */
  std::optional<std::string> make_template;
  bool write_config = false;
};

/* Prints the usage line to stderr and returns nullopt on a bad command line. */
[[nodiscard]] std::optional<Config> parse_args(int argc, char **argv);

class Syncer {
public:
  explicit Syncer(Config config) : config_(std::move(config)) {}

  void sync_now(std::string_view why = "startup");

  /* Loads the current rules, prints what they were read as, and answers one
   * (caller, target) question the same way the pairs are built. */
  void explain(std::string_view caller, std::string_view target);

  /* Every target of one caller, by name, as the policy has them. */
  void list_targets(std::string_view caller);

  /* The same set as a template HMA-OSS reads from the config, which both the
   * system server and an app process read alike. */
  void template_for(std::string_view caller, bool write);

  /* Syncs once, then keeps following the files until it is killed. */
  [[nodiscard]] bool run();

private:
  /* The rules for one readable source, with the presets they need: three
   * sources, one place, so every entry point reads the same thing. */
  struct OpenedRules {
    std::unique_ptr<Rules> rules;
    Presets presets;
  };
  [[nodiscard]] std::optional<OpenedRules>
  open_rules(const std::filesystem::path &file, const PackageDb &packages);

  /* One install or update: the "~~" directories that appeared or went away. */
  void handle_packages(const std::vector<std::string> &dirs);
  [[nodiscard]] const PackageDb *packages();

  /* Publish the current APK delta; false leaves it pending for a retry. */
  [[nodiscard]] bool publish_code_dirs();

  /* Where a config can be. Not a command line option: this reads where the apps
   * keep them. */
  const std::vector<RuleSource> sources_ = RuleSource::known();
  struct PackageStamp {
    std::int64_t mtime_sec = 0;
    std::int64_t mtime_nsec = 0;
    std::uint64_t size = 0;
    std::uint64_t inode = 0;
  };

  Config config_;
  std::optional<PackageDb> packages_;
  PackageStamp packages_stamp_;
  bool config_refused_ = false;
  bool users_refused_ = false;
  bool policy_pushed_ = false;
  bool sync_ok_ = false;
  NetlinkClient netlink_;
  Watcher watcher_;
  /* The callers of the current policy: package name -> uid, and where their
   * code lives once it is known. */
  std::map<std::string, std::uint32_t, std::less<>> callers_;
  std::map<std::string, std::filesystem::path, std::less<>> code_dirs_;

  std::vector<Pair> pushed_;
  using ApkId = std::pair<std::uint32_t, std::uint64_t>;
  enum class ApkPhase { Confirmed, Adding, Dropping };
  struct PublishedApk {
    ApkEntry entry;
    ApkPhase phase = ApkPhase::Adding;
  };
  /* A command can take effect even if its reply is lost. Adding means the
   * identity may be installed; Dropping must finish before another add for
   * that inode. Neither uncertainty may be discarded on a config change. */
  std::map<ApkId, PublishedApk> published_;
};

} // namespace uidfake

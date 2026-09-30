// SPDX-License-Identifier: GPL-2.0
#include "sync.hpp"
#include "status.hpp"

#include "oss_presets.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>

#include "common.hpp"
#include "packages.hpp"
#include "rules.hpp"

namespace uidfake {
namespace {

/* Where installed code lives; the same root the watcher reports events from. */
constexpr std::string_view kAppRoot = "/data/app";
/* The kernel takes this many caller code dirs. */
constexpr std::size_t kApkLimit = 10000;

/* One line describing what the kernel says it hooked: what the module
 * description in the KernelSU or Magisk list shows a user. */
[[nodiscard]] std::string status_line(NetlinkClient &client,
                                      std::size_t rules) {
  const auto st = client.status();
  std::string line = "ok, " + std::to_string(rules) + " rule(s)";

  if (!st) {
    line += ", status unavailable";
    if (client.unsupported())
      line += " (module older than tool)";
    return line;
  }
  /*
   * The uid counts are the syscall-table tier's: when the queries are answered
   * from a find_user copy the tables were never touched, and printing 0+0 next
   * to a working device is exactly the line that used to be misread as "nothing
   * is hooked". So the tier is what gets printed, and the counts only where
   * they mean something.
   */
  if (st->flags & KAUX_F_PRIO_INLINE)
    line += ", uid queries=find_user";
  else if (st->flags & KAUX_F_PRIO_TABLES)
    line += ", uid queries=syscall tables, uid " + std::to_string(st->native) +
            "+" + std::to_string(st->compat);
  else
    line += ", uid queries=not hidden";
  if (st->last_error)
    line += ", err=" + std::to_string(st->last_error);
  if (st->apk_inodes || st->apk_offered)
    line += ", apk " + std::to_string(st->apk_inodes);
  if (st->apk_failed)
    line += " (" + std::to_string(st->apk_failed) + " of " +
            std::to_string(st->apk_offered) + " failed)";
  else if (st->apk_failed_total)
    line += " (" + std::to_string(st->apk_failed_total) + " failed since boot)";
  /* The geometry the module was built for, against the running kernel's: the
   * fixmap address and the page tables both follow from it, and the module
   * proves its writes before making them. Saying which one is in play is what
   * turns "nothing is hooked" into something a user can act on. */
  {
    const auto device = read_device_config();

    if (device.va_bits && st->va_bits && *device.va_bits != st->va_bits)
      line += ", VA " + std::to_string(*device.va_bits) + " not the module's " +
              std::to_string(st->va_bits);
    if (device.page_shift && st->page_shift &&
        *device.page_shift != st->page_shift)
      line += ", page size is not the module's";
  }

  if (st->lsm_state == KAUX_LSM_TAKEN || st->lsm_state == KAUX_LSM_FALLBACK)
    line +=
        std::string(", setuid=") + (st->lsm_target[0] ? st->lsm_target : "?");
  else if (st->lsm_state == KAUX_LSM_FAILED)
    line += ", setuid hook failed (" + std::to_string(st->lsm_error) + ")";
  else
    line += ", setuid hook not installed";
  return line;
}

[[nodiscard]] bool dir_matches(std::string_view leaf, std::string_view pkg) {
  return leaf.size() > pkg.size() && leaf.compare(0, pkg.size(), pkg) == 0 &&
         leaf[pkg.size()] == '-';
}

} // namespace

std::optional<Config> parse_args(int argc, char **argv) {
  Config config;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--once") {
      config.once = true;
    } else if (arg == "--write-config") {
      config.write_config = true;
    } else if (arg == "--template" && i + 1 < argc) {
      config.make_template = std::string{argv[++i]};
    } else if (arg == "--list" && i + 1 < argc) {
      config.list = std::string{argv[++i]};
    } else if (arg == "--explain" && i + 2 < argc) {
      config.explain =
          std::pair{std::string{argv[++i]}, std::string{argv[++i]}};
    } else {
      std::fprintf(
          stderr,
          "usage: %s [--once] [--explain CALLER TARGET] [--list CALLER] "
          "[--template CALLER [--write-config]]\n",
          argc > 0 ? argv[0] : "sync-tool");
      return std::nullopt;
    }
  }
  return config;
}

const PackageDb *Syncer::packages() {
  struct stat info{};
  if (::stat(std::string{kPackagesXml}.c_str(), &info) != 0) {
    Log::warn("cannot read {} (will retry on the next event)", kPackagesXml);
    return nullptr;
  }

  const PackageStamp stamp{.mtime_sec = info.st_mtim.tv_sec,
                           .mtime_nsec = info.st_mtim.tv_nsec,
                           .size = (std::uint64_t)info.st_size,
                           .inode = (std::uint64_t)info.st_ino};
  const bool cached = packages_ &&
                      stamp.mtime_sec == packages_stamp_.mtime_sec &&
                      stamp.mtime_nsec == packages_stamp_.mtime_nsec &&
                      stamp.size == packages_stamp_.size &&
                      stamp.inode == packages_stamp_.inode;
  if (cached)
    return &*packages_;

  auto db = PackageDb::load(std::string{kPackagesXml});
  if (!db)
    return nullptr;
  Log::info("read {} ({} package(s))", kPackagesXml, db->by_name().size());
  packages_ = std::move(db);
  packages_stamp_ = stamp;
  return &*packages_;
}

/* One place that reads the source through its rules, with the presets' three
 * sources: the sync, --explain, --list and --template cannot disagree. */
std::optional<Syncer::OpenedRules>
Syncer::open_rules(const std::filesystem::path &file,
                   const PackageDb &packages) {
  std::unique_ptr<Rules> rules;
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (source && source->tool() == Tool::HmaOss)
    rules = HmaOssRules::load(file);
  else
    rules = HmaRules::load(file);
  if (!rules) {
    Log::warn("cannot read {}", file.string());
    return std::nullopt;
  }

  PresetFacts facts;
  Presets presets;
  if (rules->uses_presets()) {
    presets = load_preset_cache(file, facts);

    /*
     * The cache is what the app exported, and on any device that has it, it is
     * complete. Scanning is the fallback for a cache that is missing or
     * partial, and it is not free: it reads every installed apk. Only the
     * presets the config applies and the cache did not have are scanned for.
     */
    std::set<std::string, std::less<>> missing;
    for (const auto &name : rules->presets_in_use())
      if (!presets.contains(name))
        missing.insert(name);
    if (!missing.empty()) {
      Log::info("presets not in the cache, reading the apks for {} of them",
                missing.size());
      {
        ScanMap apps;

        for (const auto &[name, info] : packages.by_name())
          apps.emplace(name, ScanTarget{.uid = info.uid,
                                        .code_dir = info.code_dir,
                                        .system = info.system});
        facts.scanned = scan_presets(apps, missing);
      }
    }
  }
  rules->set_preset_facts(facts);
  return OpenedRules{.rules = std::move(rules), .presets = std::move(presets)};
}

void Syncer::sync_now(std::string_view why) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    /* Once per outage: before the unlock this used to repeat on every tick. */
    if (!config_refused_) {
      config_refused_ = true;
      Log::warn("no readable rule source yet (keeping the previous policy)");
      report_status("waiting for an HMA config");
    }
    return;
  }
  if (config_refused_) {
    config_refused_ = false;
    Log::info("rule source readable again");
  }

  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return; /* it went away between the check and the read */

  const auto users = android_users();
  if (!users) {
    if (!users_refused_) {
      users_refused_ = true;
      Log::warn("user list is not readable yet (keeping the previous policy)");
    }
    watcher_.arm_retry();
    return;
  }
  if (users_refused_) {
    users_refused_ = false;
    Log::info("user list readable again");
  }

  const auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;
  Pairs pairs = rules->expand(*packages, presets);

  /* The rules are per package, so every user answers
   * for its own uids. */
  pairs = expand_users(pairs, *users);
  std::ranges::sort(pairs, [](const Pair &a, const Pair &b) {
    return a.caller != b.caller ? a.caller < b.caller : a.target < b.target;
  });
  pairs.erase(std::unique(pairs.begin(), pairs.end(),
                          [](const Pair &a, const Pair &b) {
                            return a.caller == b.caller && a.target == b.target;
                          }),
              pairs.end());

  /* The kernel holds this many pairs; another
   * attempt cannot change the count.
   */
  if (pairs.size() > NetlinkClient::kMaxPairs) {
    Log::warn("{} pair(s) is more than the kernel "
              "holds ({}); keeping the "
              "previous policy",
              pairs.size(), NetlinkClient::kMaxPairs);
    return;
  }

  const auto same_pair = [](const Pair &a, const Pair &b) {
    return a.caller == b.caller && a.target == b.target;
  };
  if (!std::ranges::equal(pairs, pushed_, same_pair)) {
    if (!netlink_.push(pairs)) {
      /* The kernel keeps its policy, and this pass
       * asks for a retry: a module loaded a second
       * later would otherwise wait for the next
       * event. */
      watcher_.arm_retry();
      return;
    }
    pushed_.assign(pairs.begin(), pairs.end());
    Log::info("synced {} pair(s) ({})", pairs.size(), why);
    report_status(status_line(netlink_, pairs.size()));
  }

  std::set<std::uint32_t> caller_uids;
  bool wild = false;
  for (const auto &pair : pairs) {
    if (pair.caller == 0)
      wild = true;
    else
      caller_uids.insert(pair.caller);
  }

  callers_.clear();
  for (const auto &[name, info] : packages->by_name()) {
    if (wild || caller_uids.contains(info.uid))
      callers_.emplace(name, info.uid);
  }

  std::size_t missing = 0;
  for (const auto &[name, uid] : callers_) {
    const auto dir = packages->code_dir_of(name);
    if (!dir) {
      ++missing;
      continue;
    }
    code_dirs_.insert_or_assign(name, *dir);
  }
  if (missing != 0)
    Log::warn("{} caller(s) have no code directory in {}", missing,
              kPackagesXml);

  publish_code_dirs();
}

void Syncer::publish_code_dirs() {
  std::vector<ApkEntry> entries;
  entries.reserve(callers_.size());
  /* One entry per directory, even when several packages share a uid. */
  /* One entry per apk file, even when several packages share a code dir. */
  std::set<std::string, std::less<>> seen;

  /*
   * Every installed app, not only the callers: the table is what lets the
   * kernel name an isolated process by the apk it opens, and its host is
   * whatever app spawned it -- a WebView renderer, a renderer service,
   * anything. The callers go in first, so a table that hits the cap still
   * carries the ones the policy needs.
   */
  std::vector<std::pair<std::string, std::uint32_t>> wanted;
  wanted.reserve(packages_ ? packages_->by_name().size() : callers_.size());
  for (const auto &[name, uid] : callers_)
    wanted.emplace_back(name, uid);
  if (packages_) {
    for (const auto &[name, info] : packages_->by_name()) {
      if (info.uid < kFirstAppUid || callers_.contains(name))
        continue;
      wanted.emplace_back(name, info.uid);
    }
  }

  for (const auto &[name, uid] : wanted) {
    auto dir = code_dirs_.find(name);
    if (dir == code_dirs_.end() && packages_) {
      /* Not a caller: its directory comes straight from the package database.
       */
      if (const auto own = packages_->code_dir_of(name)) {
        code_dirs_.insert_or_assign(name, *own);
        dir = code_dirs_.find(name);
      }
    }
    if (dir == code_dirs_.end())
      continue;
    /*
     * Only the tree installed code lives in. An entry on another partition --
     * a system app's apk, a library under /apex -- puts that whole filesystem
     * into the kernel's set, and then any file the framework reads from it ends
     * a child's wait long before its own code is anywhere near running.
     */
    /*
     * The file a child opens first is its own base.apk, and that is the inode
     * whose open the kernel replaces, so the path to it is what goes up. A
     * system app's apk is under /system, an installed one's under /data; both
     * are files with an inode, and which partition it is on no longer matters.
     */
    const auto apk = dir->second / "base.apk";
    if (!seen.insert(apk.string()).second)
      continue;
    struct stat info{};
    if (::stat(apk.c_str(), &info) != 0)
      continue;
    if (entries.size() >= kApkLimit)
      break;
    entries.push_back(ApkEntry{.path = apk.string(),
                               .uid = uid,
                               .dev = static_cast<std::uint32_t>(info.st_dev),
                               .ino = static_cast<std::uint64_t>(info.st_ino)});
  }

  /*
   * What goes up is the difference, and only the difference: an apk that is new
   * or was replaced (same path, another inode -- an update), and one that is
   * gone (the path is no longer there, so it is named by its numbers). The
   * whole set would not fit one message on a device with many apps anyway.
   */
  /* The difference is taken through hash sets. Both loops below used to scan
   * the whole published set for every entry -- quadratic, which is a tenth of a
   * millisecond on a device with three hundred apps and a stall of up to a
   * second on one at the ten thousand apk limit, on every package event. */
  const auto key_of = [](const ApkEntry &entry) {
    return entry.path + '\0' + std::to_string(entry.dev) + '\0' +
           std::to_string(entry.ino);
  };
  std::unordered_set<std::string> known, paths, was_known;
  known.reserve(entries.size());
  paths.reserve(entries.size());
  was_known.reserve(published_.size());
  for (const auto &entry : entries) {
    known.insert(key_of(entry));
    paths.insert(entry.path);
  }
  for (const auto &old : published_)
    was_known.insert(key_of(old));

  std::vector<ApkEntry> delta;
  for (const auto &entry : entries) {
    if (!was_known.contains(key_of(entry)))
      delta.push_back(entry);
  }
  for (const auto &old : published_) {
    if (!paths.contains(old.path))
      delta.push_back(ApkEntry{.path = old.path,
                               .uid = old.uid,
                               .dev = old.dev,
                               .ino = old.ino,
                               .action = 1});
  }
  Log::info("registered {} app apk(s), {} change(s) to send", entries.size(),
            delta.size());
  if (delta.empty())
    return;
  if (!netlink_.push_apks(delta)) {
    watcher_.arm_retry();
    return;
  }
  published_.assign(entries.begin(), entries.end());
  /* the apk side moved, so the line a user reads has to move with it */
  report_status(status_line(netlink_, pushed_.size()));
}

void Syncer::handle_packages(const std::vector<std::string> &dirs) {
  /* Nothing is known before the first policy
   * arrives, and a policy change reads the whole map
   * again anyway. */
  if (callers_.empty())
    return;

  /*
   * Every install, update and removal changes which base.apk files exist, and
   * the set of those the kernel holds is what names a child -- so all of these
   * events have to reach publish_code_dirs(), not only the ones about a caller.
   * The paths come from the package database, so read it again first: its stamp
   * is what tells installs apart from noise.
   */
  if (this->packages() == nullptr)
    return;

  bool changed = false;
  for (const auto &name : dirs) {
    /* Every event, including the ones about a package that is not a caller: its
     * apk still has to be in the kernel's set, so it is worth seeing. */
    Log::info("package event: {}", name);
    changed = true;
    const std::filesystem::path base = std::filesystem::path{kAppRoot} / name;
    std::error_code ec;

    if (std::filesystem::is_directory(base, ec)) {

      for (const auto &entry : std::filesystem::directory_iterator{base, ec}) {
        if (ec)
          break;
        if (!entry.is_directory(ec))
          continue;
        const auto leaf = entry.path().filename().string();
        const auto caller = std::ranges::find_if(callers_, [&](const auto &c) {
          return dir_matches(leaf, c.first);
        });
        if (caller == callers_.end())
          continue;
        Log::info("{} now lives in {}", caller->first, entry.path().string());
        code_dirs_.insert_or_assign(caller->first, entry.path());
        changed = true;
      }
    } else {

      for (auto it = code_dirs_.begin(); it != code_dirs_.end();) {
        if (it->second.parent_path() == base) {
          Log::info("{} no longer lives in {}", it->first, it->second.string());
          it = code_dirs_.erase(it);
          changed = true;
        } else {
          ++it;
        }
      }
    }
  }

  if (changed)
    publish_code_dirs();
}

/* One decision, printed with everything it was read
 * from: the per-caller lines the expander writes,
 * the preset summary, and then the answer. */
void Syncer::explain(std::string_view caller, std::string_view target) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;

  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  /* The same call the sync makes, so its log lines
   * are the parse itself. */
  const Pairs pairs = rules->expand(*packages, presets);

  if (!packages->by_name().contains(target))
    Log::warn("{} is not in {}", target, kPackagesXml);
  const bool hidden =
      rules->hides(caller, target, packages->is_system(target), presets);
  Log::info("{}: {} hides {} = {} ({} pair(s) in "
            "the policy)",
            file->string(), caller, target, hidden ? "yes" : "no",
            pairs.size());
}

/* Every target one caller hides, by name: the same
 * list the kernel is given, printed so it can be
 * read next to what an app itself sees. */
void Syncer::list_targets(std::string_view caller) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;
  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  const Pairs pairs = rules->expand(*packages, presets);
  /* One uid can carry several package names, and the
   * kernel hides the uid: list them all, or a target
   * looks missing when it is the same uid under
   * another name. */
  std::map<std::uint32_t, std::vector<std::string>> names_of_uid;
  for (const auto &[name, info] : packages->by_name())
    names_of_uid[info.uid].push_back(std::string{name});

  std::vector<std::string> targets;
  const auto caller_uid = packages->uid_of(caller);
  if (!caller_uid) {
    Log::warn("{} is not installed", caller);
    return;
  }
  for (const auto &pair : pairs) {
    if (pair.caller != *caller_uid)
      continue;
    const auto names = names_of_uid.find(pair.target);
    if (names == names_of_uid.end()) {
      targets.push_back(std::to_string(pair.target));
      continue;
    }
    std::string joined;
    for (const auto &name : names->second) {
      if (!joined.empty())
        joined += " + ";
      joined += name;
    }
    targets.push_back(std::move(joined));
  }
  std::ranges::sort(targets);
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

  Log::info("{} hides {} target(s):", caller, targets.size());
  for (const auto &name : targets)
    Log::info("  {}", name);
}

/* The caller's hidden set as a template in the
 * config language: HMA-OSS reads a template from the
 * config in every process, while it rebuilds a
 * preset per process from a view its own hooks
 * filter. */
void Syncer::template_for(std::string_view caller, bool write) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;
  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  const Pairs pairs = rules->expand(*packages, presets);
  const auto caller_uid = packages->uid_of(caller);
  if (!caller_uid) {
    Log::warn("{} is not installed", caller);
    return;
  }

  std::vector<std::string> names;
  for (const auto &pair : pairs) {
    if (pair.caller != *caller_uid)
      continue;
    for (const auto &[name, info] : packages->by_name())
      if (info.uid == pair.target && !std::ranges::contains(names, name))
        names.emplace_back(name);
  }
  std::ranges::sort(names);
  names.erase(std::unique(names.begin(), names.end()), names.end());

  const std::string template_name = "uidfake";
  Log::info("{} hides {} package(s); the template "
            "'{}' would carry them:",
            caller, names.size(), template_name);
  nlohmann::json snippet = {
      {template_name, {{"appList", names}, {"isWhitelist", false}}}};
  Log::info("\n{}", snippet.dump(2));
  Log::info("apply it by adding \"{}\" to {}'s "
            "applyTemplates",
            template_name, caller);
  if (!write)
    return;

  /* Writing into another app's config: keep a copy,
   * write beside the file and rename, and only when
   * something actually changes. */
  std::ifstream in{*file};
  nlohmann::json config;
  try {
    in >> config;
  } catch (const std::exception &e) {
    Log::warn("cannot parse {}: {}", file->string(), e.what());
    return;
  }
  config["templates"][template_name] = {{"appList", names},
                                        {"isWhitelist", false}};
  auto &applied = config["scope"][std::string{caller}]["applyTemplates"];
  if (!applied.is_array())
    applied = nlohmann::json::array();
  if (!applied.contains(template_name))
    applied.push_back(template_name);

  const auto backup = file->string() + ".uidfake.bak";
  std::error_code ignored;
  if (!std::filesystem::exists(backup, ignored))
    std::filesystem::copy_file(*file, backup, ignored);
  const auto tmp = file->string() + ".uidfake.tmp";
  {
    std::ofstream out{tmp, std::ios::trunc};
    out << config.dump();
  }
  std::filesystem::rename(tmp, *file, ignored);
  Log::info("wrote {} (backup {})", file->string(), backup);
}

bool Syncer::run() {
  sync_now();
  if (config_.once)
    return !users_refused_;

  if (!watcher_.open(sources_))
    return false;
  if (users_refused_)
    watcher_.arm_retry();
  if (const auto active = RuleSource::active(sources_)) {
    if (const auto file = active->config())
      Log::info("watching {}", file->string());
  } else {
    Log::info("no rule config yet (waiting for the "
              "known places)");
  }

  for (;;) {
    const auto tick = watcher_.wait();
    if (!tick)
      return false;

    if (tick->kind == Watcher::Tick::Kind::Packages)
      handle_packages(tick->dirs);
    else
      sync_now(tick->kind == Watcher::Tick::Kind::Config ? "config.json changed"
                                                         : "retry");
  }
}

} // namespace uidfake

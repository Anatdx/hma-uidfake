// SPDX-License-Identifier: GPL-2.0
/*
 * preset_rules.cpp - the scanned half of HMA-OSS's presets.
 *
 * BasePreset judges an installed app with canBeAddedIntoPreset(), and the app
 * writes only the result of that to its cache. The rules themselves are here,
 * read off the preset classes: the names that need the APK are checked by
 * looking for the entry names in the file (an APK's central directory is
 * plain text), the rest by the package name.
 */

#include <filesystem>
#include <fstream>
#include <ranges>
#include <string>
#include <vector>

#include "packages.hpp"
#include "rules.hpp"

namespace uidfake {
namespace {

/* HMA-OSS never adds a package on its own reserved list to a preset. */
constexpr std::array kReserved{
    std::string_view{"android"},
    std::string_view{"android.media"},
    std::string_view{"android.uid.system"},
    std::string_view{"android.uid.shell"},
    std::string_view{"android.uid.systemui"},
    std::string_view{"com.android.permissioncontroller"},
    std::string_view{"com.android.providers.downloads"},
    std::string_view{"com.android.providers.downloads.ui"},
    std::string_view{"com.android.providers.media"},
    std::string_view{"com.android.providers.media.module"},
    std::string_view{"com.android.providers.settings"},
    std::string_view{"com.google.android.providers.media.module"},
    std::string_view{"com.google.android.permissioncontroller"},
    std::string_view{"com.miui.securitycenter"},
};

[[nodiscard]] bool
starts_with_any(std::string_view value,
                std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(
      set, [&](std::string_view one) { return value.starts_with(one); });
}

[[nodiscard]] bool ends_with_any(std::string_view value,
                                 std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(
      set, [&](std::string_view one) { return value.ends_with(one); });
}

[[nodiscard]] bool contains_any(std::string_view value,
                                std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(set, [&](std::string_view one) {
    return value.find(one) != std::string_view::npos;
  });
}

/* An APK keeps its entry names in the central directory as plain bytes, so a
 * search is enough to answer "does this file carry that entry" without
 * unpacking anything. */
/* An APK keeps its entry names in the central directory at the end of the file,
 * plain and uncompressed, so reading the tail answers "does this file carry
 * that entry" without unpacking anything. */

/* A binary AndroidManifest.xml keeps its strings in UTF-16, and the app
 * searches the manifest for its own constants written that way. Turning the
 * text into UTF-16 and looking for those bytes in the same tail answers the
 * same question. */
/* A zip entry name is plain bytes, a binary manifest string is UTF-16: try
 * both. */
[[nodiscard]] bool file_has(const std::filesystem::path &apk,
                            std::string_view text) {
  constexpr std::uintmax_t kTail = 1u << 20;
  std::error_code ignored;
  const auto size = std::filesystem::file_size(apk, ignored);
  if (ignored || size == 0)
    return false;
  const auto from = size > kTail ? size - kTail : 0;
  std::ifstream in{apk, std::ios::binary};
  if (!in)
    return false;
  in.seekg((std::streamoff)from);
  std::vector<char> data(size - from);
  in.read(data.data(), (std::streamsize)data.size());
  const auto end = data.begin() + in.gcount();
  std::string wide;
  wide.reserve(text.size() * 2);
  for (char c : text) {
    wide.push_back(c);
    wide.push_back('\0');
  }
  return std::search(data.begin(), end, text.begin(), text.end()) != end ||
         std::search(data.begin(), end, wide.begin(), wide.end()) != end;
}

[[nodiscard]] bool apk_has_any(const ScanMap &apps, std::string_view name,
                               std::initializer_list<std::string_view> texts) {
  const auto it = apps.find(std::string{name});
  if (it == apps.end())
    return false;
  const auto dir = it->second.code_dir;
  std::error_code ignored;
  for (const auto &item : std::filesystem::directory_iterator{dir, ignored}) {
    if (ignored)
      break;
    if (item.path().extension() != ".apk")
      continue;
    for (const auto &text : texts)
      if (file_has(item.path(), text))
        return true;
  }
  return false;
}

/* Every split of an app can carry entries, so all the APKs in its code
 * directory are looked at, the way HMA-OSS does. */

constexpr std::array kRootLibs{
    std::string_view{"libkernelsu.so"},
    std::string_view{"libapd.so"},
    std::string_view{"libmagisk.so"},
    std::string_view{"libmagiskboot.so"},
    std::string_view{"libmmrl-file-manager.so"},
    std::string_view{"libmmrl-kernelsu.so"},
    std::string_view{"libzakoboot.so"},
};

/* The library names live inside the APK as lib/<arch>/<name>: both ABIs HMA-OSS
 * looks at are tried. */
/* The library names live inside the APK as lib/<arch>/<name>: both ABIs HMA-OSS
 * looks at are tried. */
[[nodiscard]] bool apk_has_lib(const ScanMap &apps, std::string_view name,
                               const auto &libs) {
  for (const auto &lib : libs) {
    const std::string arm64 = std::string{"lib/arm64-v8a/"} + std::string{lib};
    const std::string arm32 =
        std::string{"lib/armeabi-v7a/"} + std::string{lib};
    if (apk_has_any(apps, name, {arm64}) || apk_has_any(apps, name, {arm32}))
      return true;
  }
  return false;
}

} // namespace

Presets load_preset_cache(const std::filesystem::path &config_file,
                          PresetFacts &facts) {
  Presets presets;
  std::error_code ignored;

  /* The new name is what the app writes now and wins when it reads, but a file
   * caught half-written, or one a writer trimmed, must not cost the device its
   * presets: the other name is read instead. */
  nlohmann::json json;
  bool have_cache = false;
  for (const auto &cache : {config_file.parent_path() / kPresetCacheNew,
                            config_file.parent_path() / kPresetCacheOld}) {
    if (!std::filesystem::exists(cache, ignored))
      continue;
    try {
      std::ifstream in{cache};
      if (!in)
        continue;
      in >> json;
      have_cache = true;
      break;
    } catch (const std::exception &e) {
      Log::warn("cannot parse {}: {}", cache.string(), e.what());
    }
  }
  if (!have_cache)
    return presets;

  // items() is a proxy into its JSON owner. Keep that owner alive for the loop,
  // including with NDK r27's compiler, which does not extend its lifetime here.
  const auto cache_entries = json.value("cache", nlohmann::json::object());
  for (const auto &[name, list] : cache_entries.items()) {
    if (!list.is_array())
      continue;
    auto &packages = presets[name];
    for (const auto &item : list)
      if (item.is_string())
        packages.insert(item.get<std::string>());
  }

  /* The same cache says which packages are connected to GMS: a preset hit still
   * leaves those visible to a caller that asks as one of the GMS packages. */
  for (const auto &item :
       json.value("riskyPackageCache", nlohmann::json::array()))
    if (item.is_string())
      facts.gms_connected.insert(item.get<std::string>());
  return presets;
}

Presets scan_presets(const ScanMap &apps,
                     const std::set<std::string, std::less<>> &wanted) {
  Presets presets;
  /* Only the presets the caller asked for pay for an apk read: the string rules
   * are free, opening a file is not. */
  const bool want_root = wanted.contains("root_apps");
  const bool want_sus = wanted.contains("sus_apps");
  const bool want_xposed = wanted.contains("xposed");
  const bool want_acc = wanted.contains("accessibility_apps");
  const bool want_shizuku = wanted.contains("shizuku_dhizuku");

  for (const auto &[name, info] : apps) {
    if (std::ranges::contains(kReserved, name))
      continue;
    const bool detector =
        starts_with_any(name, {"me.garfieldhan."}) ||
        contains_any(name, {"chunqiu", "chuqniu"}) ||
        ends_with_any(name, {".duckdetector", ".keyattestation"});
    if (detector)
      presets["detector_apps"].insert(std::string{name});

    if (!detector) {
      /* root_apps */
      if (starts_with_any(name, {"dev.ukanth.ufirewall", "xzr.", "moe.xzr.",
                                 "org.lsposed", "com.drdisagree.iconify"}) ||
          starts_with_any(name,
                          {"com.dergoogler.mmrl", "com.xayah.databackup",
                           "com.smartpack.", "org.fdroid.fdroid.privileged"}) ||
          ends_with_any(name, {".viper4android", ".viperfx", ".magisk"}) ||
          contains_any(name, {".busybox", ".apatch."}) ||
          name.ends_with(".apatch") ||
          (want_root && apk_has_lib(apps, name, kRootLibs)) ||
          apk_has_any(apps, name,
                      {"assets/gamma_profiles.json", "assets/main.jar"}))
        presets["root_apps"].insert(std::string{name});
    }

    /* sus_apps */
    if (starts_with_any(name, {"com.offsec.", "com.termux", "com.realvnc.",
                               "nextapp.fx", "com.ghisler.", "ru.zdevs.",
                               "com.mixplorer", "bin.mt.", "com.x0.strai.",
                               "com.microsoft.rdc.", "com.teamviewer."}) ||
        (want_sus && apk_has_any(apps, name,
                                 {"assets/APKEditor.pk8", "assets/testkey.pk8",
                                  "assets/key/testkey.pk8"})))
      presets["sus_apps"].insert(std::string{name});

    if (want_root && !detector &&
        (contains_any(name, {".busybox", ".apatch."}) ||
         ends_with_any(name,
                       {".viper4android", ".viperfx", ".magisk", ".apatch"}) ||
         starts_with_any(name,
                         {"com.smartpack.", "org.fdroid.fdroid.privileged"}) ||
         apk_has_any(apps, name,
                     {"libkernelsu.so", "libapd.so", "libmagisk.so",
                      "libmagiskboot.so", "libmmrl-file-manager.so",
                      "libmmrl-kernelsu.so", "libzakoboot.so",
                      "gamma_profiles.json", "main.jar"})))
      presets["root_apps"].insert(std::string{name});

    if (want_sus &&
        (starts_with_any(name, {"com.offsec.", "com.termux", "com.realvnc.",
                                "bin.mt.", "com.x0.strai.",
                                "com.microsoft.rdc.", "com.teamviewer."}) ||
         apk_has_any(apps, name,
                     {"APKEditor.pk8", "testkey.pk8", "key/testkey.pk8"})))
      presets["sus_apps"].insert(std::string{name});

    /* accessibility_apps */
    /* A system app never goes into accessibility_apps (reloadPresets says so).
     */
    if (want_acc && !detector && !info.system &&
        apk_has_any(apps, name,
                    {"android.permission.BIND_ACCESSIBILITY_SERVICE"}))
      presets["accessibility_apps"].insert(std::string{name});

    /* shizuku_dhizuku: the prefix above, or the provider the manifest names */
    if (want_shizuku && apk_has_any(apps, name,
                                    {"rikka.shizuku.ShizukuProvider",
                                     "com.rosan.dhizuku.server.provider"}))
      presets["shizuku_dhizuku"].insert(std::string{name});

    /* root_apps by the old superuser permission, unless the manifest is
     * whitelisted */
    if (want_root && !detector &&
        apk_has_any(apps, name, {"android.permission.ACCESS_SUPERUSER"}) &&
        !apk_has_any(apps, name,
                     {"org.mozilla.gecko", "MEIZUPUSH", "hk.alipay.wallet",
                      "com.tencent.mm", "com.heytap.", "com.netmera.Netmera"}))
      presets["root_apps"].insert(std::string{name});

    /* xposed */
    if (want_xposed &&
        apk_has_any(apps, name,
                    {"assets/xposed_init", "META-INF/xposed/module.prop"}))
      presets["xposed"].insert(std::string{name});
    /* The manager writes itself into this preset (XposedModulesPreset), so that
     * half lives in oss_presets.hpp with every other preset's written-in half.
     */

    /* shizuku_dhizuku */
    if (name.starts_with("moe.shizuku."))
      presets["shizuku_dhizuku"].insert(std::string{name});

    /* custom_rom */
    if (starts_with_any(name, {"lineageos.",
                               "org.lineageos.",
                               "com.caf.",
                               "org.calyxos.",
                               "co.aospa.",
                               "org.omnirom.",
                               "org.protonaosp.",
                               "org.evolution.",
                               "org.evolutionx.",
                               "com.android.system.",
                               "com.accents.",
                               "com.alpha.",
                               "com.android.systemui.",
                               "com.android.theme.",
                               "com.bootleggers.",
                               "com.custom.overlay.",
                               "com.gnonymous.gvisualmod.",
                               "com.libremobileos.",
                               "com.nikgapps.",
                               "com.potato.",
                               "eu.xiaomi."}) ||
        ends_with_any(name, {".evolution", ".evolutionx", ".overlay.fog"}))
      if (starts_with_any(name, {

                                }))
        presets["custom_rom"].insert(std::string{name});

    presets["custom_rom"].insert(std::string{name});
  }
  return presets;
}

} // namespace uidfake

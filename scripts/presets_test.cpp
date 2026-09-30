// SPDX-License-Identifier: GPL-2.0
// Regression test for the OSS presets: every case names the line of HMA-OSS's
// app_presets/*.kt it stands for.
#include "oss_presets.hpp"
#include "rules.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>

namespace
{

int failures = 0;
uidfake::Presets g_presets;
uidfake::ScanMap g_apps;

/* The bytes a binary AndroidManifest.xml holds for this text. */
std::string utf16(std::string_view text)
{
	std::string out;
	for (char c : text) {
		out.push_back(c);
		out.push_back('\0');
	}
	return out;
}

void dump(std::string_view pkg)
{
	std::fprintf(stderr, "      %.*s is in:", (int)pkg.size(), pkg.data());
	for (const auto &[preset, set] : g_presets)
		if (set.contains(std::string{ pkg }))
			std::fprintf(stderr, " %s", preset.c_str());
	std::fprintf(stderr, "\n");
}

bool in(std::string_view preset, std::string_view pkg)
{
	const auto it = g_presets.find(std::string{ preset });
	return it != g_presets.end() && it->second.contains(std::string{ pkg });
}

/* The half HMA-OSS keeps in code: its own cache never carries it. */
bool in_static(std::string_view preset, std::string_view pkg)
{
	for (const auto &entry : uidfake::oss_presets::kStatic) {
		if (entry.name != preset)
			continue;
		for (std::size_t i = 0; i < entry.count; ++i)
			if (entry.packages[i] == pkg)
				return true;
	}
	return false;
}

void check(bool got, bool want, std::string_view preset, std::string_view pkg,
	   const char *what)
{
	if (got == want)
		return;
	std::fprintf(stderr, "presets: FAILED (%s: %s %.*s: got %d, want %d)\n",
		     what, std::string{ preset }.c_str(), (int)pkg.size(),
		     pkg.data(), got, want);
	dump(pkg);
	++failures;
}

void put_file(const std::filesystem::path &path, std::string_view bytes)
{
	std::filesystem::create_directories(path.parent_path());
	std::ofstream out{ path, std::ios::binary };
	out.write(bytes.data(), (std::streamsize)bytes.size());
}

std::filesystem::path g_root;

} // namespace

int main()
{
	g_root = std::filesystem::path{ "build" } / "presets_data";
	std::filesystem::remove_all(g_root);

	const auto add = [&](std::string_view pkg, std::string_view bytes,
			     bool system = false) {
		const auto dir = g_root / pkg;
		std::filesystem::create_directories(dir);
		put_file(dir / "base.apk", bytes);
		uidfake::ScanMap::mapped_type target;
		target.code_dir = dir;
		target.system = system;
		g_apps.emplace(std::string{ pkg }, target);
	};

	/* Apk entry bytes: a zip local header begins with PK\3\4, written out so no
	 * escape can swallow the next character. */
	const std::string pk{ 'P', 'K', 3, 4 };

	add("com.termux", "");
	add("com.termux.api", "");
	add("com.llsl.viper4android", "");
	add("com.smartpack.kernelmanager", "");
	add("org.fdroid.fdroid.privileged", "");
	add("com.offsec.nethunter", "");
	add("bin.mt.plus", "");
	add("eu.xiaomi.something", "");
	add("org.evolution.x", "");
	add("com.potato.overlay", "");
	add("me.garfieldhan.probe", "");
	add("com.miui.securitycenter", "");
	add("org.frknkrc44.hma_oss", "");
	add("com.example.libs", pk + "libkernelsu.so");
	add("com.example.assets", pk + "gamma_profiles.json");
	add("com.example.editor", pk + "APKEditor.pk8");
	add("com.example.superuser",
	    utf16("android.permission.ACCESS_SUPERUSER"));
	add("com.example.mozilla_gecko",
	    utf16("android.permission.ACCESS_SUPERUSER") +
		    utf16("org.mozilla.gecko"));
	add("com.example.a11y",
	    utf16("android.permission.BIND_ACCESSIBILITY_SERVICE"));
	add("com.example.a11y_system",
	    utf16("android.permission.BIND_ACCESSIBILITY_SERVICE"), true);
	add("com.example.shizuku", utf16("rikka.shizuku.ShizukuProvider"));
	add("com.example.xposed_legacy", pk + "assets/xposed_init");

	std::set<std::string, std::less<> > wanted{
		"detector_apps", "root_apps",	       "sus_apps",
		"custom_rom",	 "accessibility_apps", "shizuku_dhizuku",
		"xposed"
	};
	g_presets = uidfake::scan_presets(g_apps, wanted);

	check(in("sus_apps", "com.termux"), true, "sus_apps", "com.termux",
	      "termux");
	check(in("sus_apps", "com.termux.api"), true, "sus_apps",
	      "com.termux.api", "termux api");
	check(in("sus_apps", "com.offsec.nethunter"), true, "sus_apps",
	      "com.offsec.nethunter", "offsec");
	check(in("sus_apps", "bin.mt.plus"), true, "sus_apps", "bin.mt.plus",
	      "mt manager");
	check(in("sus_apps", "com.example.editor"), true, "sus_apps",
	      "com.example.editor", "apk editor asset");
	check(in("root_apps", "com.llsl.viper4android"), true, "root_apps",
	      "com.llsl.viper4android", "viper suffix");
	check(in("root_apps", "com.smartpack.kernelmanager"), true, "root_apps",
	      "com.smartpack.kernelmanager", "smartpack");
	check(in("root_apps", "org.fdroid.fdroid.privileged"), true,
	      "root_apps", "org.fdroid.fdroid.privileged",
	      "f-droid privileged");
	check(in("root_apps", "com.example.libs"), true, "root_apps",
	      "com.example.libs", "kernel manager lib");
	check(in("root_apps", "com.example.assets"), true, "root_apps",
	      "com.example.assets", "gamma profiles");
	check(in("root_apps", "com.example.superuser"), true, "root_apps",
	      "com.example.superuser", "ACCESS_SUPERUSER");
	check(in("root_apps", "com.example.mozilla_gecko"), false, "root_apps",
	      "com.example.mozilla_gecko", "whitelisted manifest");
	check(in("detector_apps", "me.garfieldhan.probe"), true,
	      "detector_apps", "me.garfieldhan.probe", "garfieldhan");
	check(in("root_apps", "me.garfieldhan.probe"), false, "root_apps",
	      "me.garfieldhan.probe", "detector kept out of root");
	check(in("accessibility_apps", "com.example.a11y"), true,
	      "accessibility_apps", "com.example.a11y", "a11y permission");
	check(in("accessibility_apps", "com.example.a11y_system"), false,
	      "accessibility_apps", "com.example.a11y_system", "system app");
	check(in("shizuku_dhizuku", "com.example.shizuku"), true,
	      "shizuku_dhizuku", "com.example.shizuku", "shizuku provider");
	check(in("xposed", "com.example.xposed_legacy"), true, "xposed",
	      "com.example.xposed_legacy", "legacy entry");
	/* XposedModulesPreset.exactPackageNames is BuildConfig.APP_PACKAGE_NAME: the
	 * app writes itself in, and the scan cannot see that, the cache does not
	 * carry it. */
	check(in_static("xposed", "org.frknkrc44.hma_oss"), true, "xposed",
	      "org.frknkrc44.hma_oss", "the app itself");
	check(in("custom_rom", "eu.xiaomi.something"), true, "custom_rom",
	      "eu.xiaomi.something", "xiaomi.eu");
	check(in("custom_rom", "org.evolution.x"), true, "custom_rom",
	      "org.evolution.x", "evolution");
	check(in("custom_rom", "com.potato.overlay"), true, "custom_rom",
	      "com.potato.overlay", "overlay prefix from the app list");
	check(in("sus_apps", "com.miui.securitycenter"), false, "sus_apps",
	      "com.miui.securitycenter", "packagesShouldNotHide");
	check(in("root_apps", "com.miui.securitycenter"), false, "root_apps",
	      "com.miui.securitycenter", "packagesShouldNotHide");

	if (failures != 0) {
		std::fprintf(stderr, "presets: %d case(s) failed\n", failures);
		return 1;
	}
	std::printf("presets: PASS\n");
	return 0;
}

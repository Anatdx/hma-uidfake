// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the package database. The platform writes it in Android's binary
 * form, a few builds write it as plain XML, and both have to give PackageDb::load
 * the same names, app ids, code paths and system flags. The fixtures below are
 * the smallest documents that carry those.
 */
#include "packages.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace
{

int failures = 0;

void check(bool got, bool want, const char *what)
{
	if (got == want)
		return;
	std::fprintf(stderr, "packages: FAILED (%s: got %d, want %d)\n", what,
		     got, want);
	++failures;
}

/*
 * One package on a system partition with no flags at all, one on data with the
 * flag word present and clear, one on data with FLAG_SYSTEM set in publicFlags
 * (the name the text writer uses for it) and one that joins a shared user
 * declared further down the file.
 */
constexpr auto kText =
	R"(<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<packages>
    <version sdkVersion="36" databaseVersion="3" />
    <!-- a comment, which the reader has to pass over -->
    <package name="com.example.system" codePath="/system/priv-app/System/System.apk" userId="10042" />
    <package name="com.example.data" codePath="/data/app/~~x/Data-y/base.apk" userId="10427" publicFlags="0" />
    <package name="com.example.flagged" codePath="/data/app/~~z/Flagged-w/base.apk" userId="10099" publicFlags="1" />
    <package name="com.example.shared" codePath="/data/app/~~s/Shared-v/base.apk" sharedUserId="com.example.sys" />
    <shared-user name="com.example.sys" userId="1000" />
</packages>
)";

std::filesystem::path write(const char *name, std::string_view bytes)
{
	const std::filesystem::path path =
		std::filesystem::path{ "build" } / "packages_data" / name;
	std::filesystem::create_directories(path.parent_path());
	std::ofstream out{ path, std::ios::binary };
	out.write(bytes.data(), (std::streamsize)bytes.size());
	return path;
}

void test_text_form()
{
	const auto path = write("packages.xml", kText);
	const auto db = uidfake::PackageDb::load(path);
	check(db.has_value(), true, "the text form is read");

	const auto uid = db->uid_of("com.example.system");
	check(uid.has_value() && *uid == 10042, true, "userId is the app id");
	check(db->is_system("com.example.system"), true,
	      "a system partition is a system app");
	check(db->is_system("com.example.data"), false,
	      "data with publicFlags 0 is not");
	check(db->is_system("com.example.flagged"), true,
	      "publicFlags carries FLAG_SYSTEM");
	const auto dir = db->code_dir_of("com.example.data");
	check(dir.has_value() && dir->string() == "/data/app/~~x/Data-y", true,
	      "base.apk drops for its directory");
	const auto shared = db->uid_of("com.example.shared");
	check(shared.has_value() && *shared == 1000, true,
	      "a shared user declared later is resolved");
	check(db->by_name().size() == 4, true,
	      "every package is in the database");
}

/* A file that is neither form must be refused, not half read. */
void test_neither_form()
{
	const auto path = write("garbage.xml", "not a package database at all");
	check(!uidfake::PackageDb::load(path).has_value(), true,
	      "a file that is neither form is refused");
}

} // namespace

int main()
{
	test_text_form();
	test_neither_form();
	if (failures != 0) {
		std::fprintf(stderr, "packages: %d case(s) failed\n", failures);
		return 1;
	}
	std::printf("packages: PASS\n");
	return 0;
}

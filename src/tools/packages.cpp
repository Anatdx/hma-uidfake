// SPDX-License-Identifier: GPL-2.0
#include "packages.hpp"

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <algorithm>

#include "common.hpp"
#include "packages_xml.hpp"

namespace uidfake {
namespace {

/* ApplicationInfo.FLAG_SYSTEM. */
constexpr std::uint64_t kFlagSystem = 1U << 0;

/* The attribute names packages.xml uses for what we need. */
constexpr std::string_view kSharedUser = "shared-user";
constexpr std::string_view kName = "name";
constexpr std::string_view kUserId = "userId";
constexpr std::string_view kSharedUserId = "sharedUserId";
constexpr std::string_view kCodePath = "codePath";
constexpr std::string_view kFlags = "flags";
/* ApplicationInfo.FLAG_SYSTEM lives in publicFlags in the text form of the
 * file; it is the same bit, under the name that writer uses. */
constexpr std::string_view kPublicFlags = "publicFlags";

/* All digits, and small enough to be a uid. */
[[nodiscard]] bool parse_number(std::string_view text, std::uint32_t &out) {
  if (text.empty() || text.size() > 10)
    return false;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9')
      return false;
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (value == 0 || value >= (1ULL << 31))
    return false;
  out = static_cast<std::uint32_t>(value);
  return true;
}

} // namespace

std::optional<std::uint32_t> parse_user_id(std::string_view text) {
  if (text.empty() || text.size() > 10)
    return std::nullopt;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9')
      return std::nullopt;
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (value >= (1ULL << 31))
    return std::nullopt;
  return static_cast<std::uint32_t>(value);
}

namespace {

[[nodiscard]] bool system_partition(std::string_view path) {
  for (const std::string_view prefix : {"/system/", "/system_ext/", "/product/",
                                        "/vendor/", "/odm/", "/apex/"}) {
    if (path.starts_with(prefix))
      return true;
  }
  return false;
}

/* The part of a code path that names the package: /data/app/~~X/pkg-Y/base.apk
 * -> /data/app/~~X/pkg-Y. */
[[nodiscard]] std::filesystem::path
code_dir_of_path(std::string_view code_path) {
  const std::filesystem::path path{code_path};
  return path.filename() == "base.apk" ? path.parent_path() : path;
}

} // namespace

std::optional<PackageDb>
PackageDb::load(const std::filesystem::path &xml_path) {
  std::ifstream in(xml_path, std::ios::binary);
  if (!in)
    return std::nullopt;

  const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                        std::istreambuf_iterator<char>());
  if (bytes.empty())
    return std::nullopt;

  PackageDb db;
  /* Shared user ids are declared once, after the packages that join them, so
   * they are collected first and resolved once the whole file is read. */
  std::map<std::string, std::uint32_t, std::less<>> shared_users;
  std::map<std::string, std::string, std::less<>> pending_shared;

  /*
   * One loop for both forms of the document: whichever reader fits the bytes
   * hands it the same events, so the two formats cannot drift apart in what
   * this program sees.
   */
  const auto read = [&](auto &reader) {
    /* The element whose attributes are being read; nested elements (perms,
     * items, signing keys) have their own "name" attributes and must not touch
     * this. */
    std::vector<std::string> stack;
    std::string name;
    std::string shared_id;
    std::string code_path;
    std::uint32_t user_id = 0;
    bool have_uid = false;
    bool have_flags = false;
    bool system_flag = false;

    for (;;) {
      const packages_xml::Event event = reader.next();
      if (event.kind == packages_xml::Event::Kind::Bad ||
          event.kind == packages_xml::Event::Kind::EndDocument)
        break;
      if (event.kind == packages_xml::Event::Kind::StartTag) {
        const std::string tag{event.name};
        stack.push_back(tag);
        if (tag == "package" || tag == kSharedUser) {
          name.clear();
          shared_id.clear();
          code_path.clear();
          user_id = 0;
          have_uid = false;
          have_flags = false;
          system_flag = false;
        }
        continue;
      }
      if (event.kind == packages_xml::Event::Kind::Attribute) {
        /* Only the element that was started last owns these. */
        const bool on_package = !stack.empty() && stack.back() == "package";
        const bool on_shared = !stack.empty() && stack.back() == kSharedUser;
        if ((!on_package && !on_shared) || event.numeric) {
          if ((on_package || on_shared) && event.numeric &&
              event.name == kUserId) {
            user_id = static_cast<std::uint32_t>(event.number);
            have_uid = true;
          } else if (on_package && event.numeric &&
                     (event.name == kFlags ||
                      (event.name == kPublicFlags && !have_flags))) {
            system_flag = (event.number & kFlagSystem) != 0;
            have_flags = true;
          } else if (on_package && event.numeric &&
                     event.name == kSharedUserId) {
            /* A shared user id is often just the number; the name form is
             * looked up in the <shared-user> elements once the file has been
             * read. */
            shared_id = std::to_string(event.number);
          }
          continue;
        }
        if (event.name == kName)
          name.assign(event.value);
        else if (on_package && event.name == kSharedUserId)
          shared_id.assign(event.value);
        else if (on_package && event.name == kCodePath)
          code_path.assign(event.value);
        continue;
      }
      if (event.kind != packages_xml::Event::Kind::EndTag)
        continue;
      const std::string tag = stack.empty() ? std::string{} : stack.back();
      if (!stack.empty())
        stack.pop_back();
      if (tag == kSharedUser && !name.empty() && have_uid) {
        shared_users[name] = user_id;
      } else if (tag == "package" && !name.empty()) {
        PackageInfo info;
        info.uid = have_uid ? user_id : 0;
        info.code_dir = code_path.empty() ? std::filesystem::path{}
                                          : code_dir_of_path(code_path);
        /* The stored flag is the real answer; the partition a package was
         * installed on is the fallback for a file that does not carry it. */
        info.system = have_flags
                          ? system_flag
                          : (!code_path.empty() && system_partition(code_path));
        db.by_name_.insert_or_assign(name, std::move(info));
        if (!have_uid && !shared_id.empty())
          pending_shared[name] = shared_id;
      }
    }

    for (const auto &[pkg, id] : pending_shared) {
      /* A shared user id is either written out as the number itself or as the
       * name of a <shared-user> declared further down the file. */
      std::uint32_t uid = 0;
      if (!parse_number(id, uid)) {
        const auto shared = shared_users.find(id);
        if (shared == shared_users.end())
          continue;
        uid = shared->second;
      }
      const auto info = db.by_name_.find(pkg);
      if (info != db.by_name_.end())
        info->second.uid = uid;
    }

    if (reader.failed()) {
      /* The stream stopped somewhere unexpected: refuse the whole file rather
       * than act on what was read so far. */
      Log::warn("{} is not a readable package database (stopped at byte {} on "
                "0x{:02x}); keeping the previous one",
                xml_path.string(), reader.bad_offset(), reader.bad_byte());
      return false;
    }
    return true;
  };

  /*
   * One reader for both forms of the document: the entry picks by content, and
   * the loop above sees the same events either way. A file that is neither form
   * is refused with what it starts with in the log, rather than guessed at.
   */
  const packages_xml::Form format = packages_xml::form(bytes);
  if (format == packages_xml::Form::Unknown) {
    /* Name what the file starts with, and where a document would have started
     * if something is sitting in front of it. */
    std::size_t first_tag = bytes.size();
    for (std::size_t i = 0; i < bytes.size() && i < 64; ++i) {
      if (bytes[i] == '<') {
        first_tag = i;
        break;
      }
    }
    if (bytes.size() < 4) {
      Log::warn("{} holds {} byte(s), not a package database",
                xml_path.string(), bytes.size());
    } else if (first_tag < bytes.size()) {
      Log::warn(
          "{} starts with {:02x} {:02x} {:02x} {:02x} and its first '<' is "
          "at byte {}, which is neither the binary nor the text form of a "
          "package database",
          xml_path.string(), bytes[0], bytes[1], bytes[2], bytes[3], first_tag);
    } else {
      Log::warn(
          "{} starts with {:02x} {:02x} {:02x} {:02x} and holds no '<' in "
          "its first 64 bytes, which is neither the binary nor the text "
          "form of a package database",
          xml_path.string(), bytes[0], bytes[1], bytes[2], bytes[3]);
    }
    return std::nullopt;
  }

  packages_xml::Reader reader{bytes};
  const bool readable = read(reader);
  if (!readable)
    return std::nullopt;
  if (!readable)
    return std::nullopt;
  if (db.by_name_.empty()) {
    Log::warn("{} lists no package", xml_path.string());
    return std::nullopt;
  }
  return db;
}

std::optional<std::uint32_t> PackageDb::uid_of(std::string_view name) const {
  const auto it = by_name_.find(name);
  if (it == by_name_.end() || it->second.uid == 0)
    return std::nullopt;
  return it->second.uid;
}

bool PackageDb::is_system(std::string_view name) const {
  const auto it = by_name_.find(name);
  return it != by_name_.end() && it->second.system;
}

std::optional<std::filesystem::path>
PackageDb::code_dir_of(std::string_view name) const {
  const auto it = by_name_.find(name);
  if (it == by_name_.end() || it->second.code_dir.empty())
    return std::nullopt;
  return it->second.code_dir;
}

/* The users this device has: the directory names under /data/system/users are
 * the ids. A failed or partial listing is not a usable user set. */
std::optional<std::vector<std::uint32_t>> android_users() {
  std::vector<std::uint32_t> users;
  std::error_code ec;
  std::filesystem::directory_iterator it{"/data/system/users", ec};
  if (ec)
    return std::nullopt;

  const std::filesystem::directory_iterator end;
  for (; it != end; it.increment(ec)) {
    if (ec)
      return std::nullopt;
    if (const auto user = parse_user_id(it->path().filename().string()))
      users.push_back(*user);
  }
  if (ec || users.empty())
    return std::nullopt;

  std::ranges::sort(users);
  users.erase(std::ranges::unique(users).begin(), users.end());
  return users;
}

Pairs expand_users(const Pairs &pairs,
                   const std::vector<std::uint32_t> &users) {
  Pairs out;
  out.reserve(pairs.size() * users.size());
  for (const std::uint32_t user : users) {
    const std::uint32_t base = user * kUserSpan;

    for (const auto &pair : pairs) {
      /* The kernel drops a system uid as a target; it is one in no user. */
      if (pair.target < kFirstAppUid)
        continue;
      out.push_back(Pair{.caller = pair.caller == 0 ? 0 : pair.caller + base,
                         .target = pair.target + base});
    }
  }
  return out;
}

} // namespace uidfake

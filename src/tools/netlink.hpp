// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "common.hpp"
#include "kaux.h" /* the wire format, shared with the module */

namespace uidfake {

/* One apk of an app that has rules: the numbers the kernel compares, nothing
 * else. */
struct ApkEntry {
  std::string path; /* the app's base.apk, what its children open first */
  std::uint32_t uid = 0;
  /* st_dev/st_ino as stat(2) reports them: what says the file is the same one,
   * and what asks for it back when only the numbers are left. */
  std::uint32_t dev = 0;
  std::uint64_t ino = 0;
  /* 1 puts the file back instead of replacing it, so a package change can be
   * sent as the difference it is. */
  std::uint32_t action = 0;
};

/*
 * Talks to the module's generic netlink family. The family itself only accepts
 * requests from processes holding CAP_NET_ADMIN and is invisible to app
 * domains, so the policy never travels over a path an app could read.
 */
class NetlinkClient {
public:
  NetlinkClient() = default;

  NetlinkClient(const NetlinkClient &) = delete;
  NetlinkClient &operator=(const NetlinkClient &) = delete;

  /* The kernel holds at most POLICY_MAX_PAIRS pairs (src/include/uidfake.h),
   * and one page carries kPagePairs of them. */
  static constexpr std::size_t kMaxPairs = 65536;

  /* Replaces the kernel's policy with `pairs` (an empty list clears it).
   * Failures are logged; false means the kernel side is not reachable yet. */
  [[nodiscard]] bool push(std::span<const Pair> pairs);

  /* What the module says it hooked, straight from the kernel (KAUX_CMD_STATUS).
   * Empty when it does not answer, which is what a module that is not loaded
   * looks like. */
  [[nodiscard]] std::optional<kaux_status> status();
  /* True when the kernel refused a command it does not know: the module that is
   * loaded was built before the command existed. */
  [[nodiscard]] bool unsupported() const { return unsupported_; }

  /* Applies caller-APK inode deltas. Removal needs explicit action=1 entries;
   * an empty list has no effect on the kernel's existing records. */
  [[nodiscard]] bool push_apks(std::span<const ApkEntry> entries);

  /* One staged upload: begin, pages of at most kPageBytes, commit. */
  [[nodiscard]] bool send_staged(std::uint32_t kind,
                                 std::span<const std::byte> bytes);

private:
  static constexpr std::string_view kFamilyName = KAUX_FAMILY_NAME;
  /* Must match the enum and the version in src/netlink.c. */
  /* The commands, attributes and blob kinds are the shared wire format in
   * include/kaux.h -- the file the module includes too, so a command that moves
   * on one side moves on the other or the build stops here. */
  static constexpr std::size_t kReplySize = 4096;

  /* One line per outage, and one when it ends. */
  void note_reachable();
  [[nodiscard]] bool ensure_connected();
  [[nodiscard]] bool send_paged(std::span<const Pair> pairs);
  [[nodiscard]] bool send_command(std::uint8_t cmd,
                                  std::span<const std::byte> blob);
  [[nodiscard]] std::optional<std::uint16_t> resolve_family();
  [[nodiscard]] bool exchange(std::span<const std::byte> request,
                              std::span<std::byte> reply);
  /* Bytes the last exchange received, so a reply can be walked. */
  std::size_t reply_bytes_ = 0;
  bool unsupported_ = false;

  Fd socket_;
  std::optional<std::uint16_t> family_;
  /* One line per outage, not one per attempt: the syncer retries while the
   * module is not loaded, and the same warning every ten seconds is noise. */
  bool warned_ = false;
  std::uint32_t seq_ = 0; /* one per request; replies are matched against it */
};

} // namespace uidfake

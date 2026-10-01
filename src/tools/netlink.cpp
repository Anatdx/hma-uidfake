// SPDX-License-Identifier: GPL-2.0
#include "netlink.hpp"
#include "status.hpp"

#include "paging.hpp"

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstring>
#include <vector>

namespace uidfake {
namespace {

/*
 * The NDK UAPI headers only ship NLA_ALIGN/NLA_HDRLEN plus macros that do not
 * handle const pointers, so iterate explicitly with a byte cursor and these two
 * predicates.
 */
[[nodiscard]] bool nlmsg_ok(const nlmsghdr *header, int left) {
  return left >= static_cast<int>(sizeof(nlmsghdr)) &&
         header->nlmsg_len >= sizeof(nlmsghdr) &&
         static_cast<int>(header->nlmsg_len) <= left;
}

[[nodiscard]] bool nlattr_ok(const nlattr *attr, int left) {
  return left >= static_cast<int>(sizeof(nlattr)) &&
         attr->nla_len >= sizeof(nlattr) &&
         static_cast<int>(attr->nla_len) <= left;
}

[[nodiscard]] const nlmsghdr *nlmsg_next(const nlmsghdr *header) {
  return reinterpret_cast<const nlmsghdr *>(
      reinterpret_cast<const std::byte *>(header) +
      NLMSG_ALIGN(header->nlmsg_len));
}

[[nodiscard]] const nlattr *nlattr_next(const nlattr *attr) {
  return reinterpret_cast<const nlattr *>(
      reinterpret_cast<const std::byte *>(attr) + NLA_ALIGN(attr->nla_len));
}

/* Little endian, matching the kernel side (see src/netlink.c). */
void store_u32(std::span<std::byte> out, std::size_t index,
               std::uint32_t value) {
  out[index + 0] = static_cast<std::byte>(value & 0xff);
  out[index + 1] = static_cast<std::byte>((value >> 8) & 0xff);
  out[index + 2] = static_cast<std::byte>((value >> 16) & 0xff);
  out[index + 3] = static_cast<std::byte>((value >> 24) & 0xff);
}

/* A netlink buffer with typed views into its header area. */
struct Buffer {
  std::vector<std::byte> bytes;

  [[nodiscard]] nlmsghdr *nlmsg() {
    return reinterpret_cast<nlmsghdr *>(bytes.data());
  }
  [[nodiscard]] genlmsghdr *genlmsg() {
    return reinterpret_cast<genlmsghdr *>(bytes.data() + NLMSG_HDRLEN);
  }
};

} // namespace

bool NetlinkClient::exchange(std::span<const std::byte> request,
                             std::span<std::byte> reply) {
  sockaddr_nl address{};
  address.nl_family = AF_NETLINK;

  iovec iov{.iov_base = const_cast<std::byte *>(request.data()),
            .iov_len = request.size()};
  msghdr message{};
  message.msg_name = &address;
  message.msg_namelen = sizeof(address);
  message.msg_iov = &iov;
  message.msg_iovlen = 1;

  if (::sendmsg(socket_.get(), &message, 0) < 0) {
    Log::warn("sendmsg: {}", std::strerror(errno));
    return false;
  }

  iov.iov_base = reply.data();
  iov.iov_len = reply.size();
  const ssize_t received = ::recvmsg(socket_.get(), &message, 0);
  if (received < 0) {
    /* EAGAIN is the read deadline firing: the module is gone or never answered.
     */
    Log::warn("recvmsg: {}", errno == EAGAIN
                                 ? "timed out waiting for the kernel"
                                 : std::strerror(errno));
    return false;
  }

  reply_bytes_ = static_cast<std::size_t>(received);
  const auto *header = reinterpret_cast<const nlmsghdr *>(reply.data());
  bool answered = false;
  for (int left = static_cast<int>(received); nlmsg_ok(header, left);) {
    const int step = static_cast<int>(NLMSG_ALIGN(header->nlmsg_len));
    if (header->nlmsg_seq != seq_) {
      /* A late reply to a request that already timed out; ignore it. */
      left -= step;
      header = nlmsg_next(header);
      continue;
    }
    if (header->nlmsg_type == NLMSG_ERROR) {
      const auto *error =
          reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
      if (error->error != 0) {
        /* A module older than this tool does not know the command; that is
         * worth telling apart from a module that is not there at all. */
        if (error->error == -EOPNOTSUPP || error->error == -EPROTONOSUPPORT)
          unsupported_ = true;
        Log::warn("netlink error: {}", std::strerror(-error->error));
        return false;
      }
    }
    answered = true;
    left -= step;
    header = nlmsg_next(header);
  }
  return answered;
}

std::optional<std::uint16_t> NetlinkClient::resolve_family() {
  if (!ensure_connected())
    return std::nullopt;

  Buffer request{};
  const std::size_t name_len = kFamilyName.size() + 1;
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN) + NLA_HDRLEN + name_len,
                       std::byte{0});

  auto *nlh = request.nlmsg();
  nlh->nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN + NLA_HDRLEN + static_cast<int>(name_len));
  nlh->nlmsg_type = GENL_ID_CTRL;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_seq = ++seq_;

  auto *genl = request.genlmsg();
  genl->cmd = CTRL_CMD_GETFAMILY;
  genl->version = 1;

  auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(genl) +
                                          GENL_HDRLEN);
  attr->nla_type = CTRL_ATTR_FAMILY_NAME;
  attr->nla_len = NLA_HDRLEN + static_cast<int>(name_len);
  std::memcpy(reinterpret_cast<std::byte *>(attr) + NLA_HDRLEN,
              kFamilyName.data(), name_len);

  std::vector<std::byte> reply(kReplySize);
  if (!exchange(request.bytes, reply))
    return std::nullopt;

  const auto *header = reinterpret_cast<const nlmsghdr *>(reply.data());
  for (int left = static_cast<int>(reply.size()); nlmsg_ok(header, left);) {
    if (header->nlmsg_type == NLMSG_ERROR)
      break;

    const auto *genl = reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
    int attr_left = static_cast<int>(header->nlmsg_len) -
                    static_cast<int>(NLMSG_LENGTH(GENL_HDRLEN));
    const auto *attr = reinterpret_cast<const nlattr *>(
        reinterpret_cast<const std::byte *>(genl) + GENL_HDRLEN);
    while (nlattr_ok(attr, attr_left)) {
      if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
        std::uint16_t id = 0;
        std::memcpy(&id, reinterpret_cast<const std::byte *>(attr) + NLA_HDRLEN,
                    sizeof(id));
        return id;
      }
      attr_left -= static_cast<int>(NLA_ALIGN(attr->nla_len));
      attr = nlattr_next(attr);
    }

    left -= static_cast<int>(NLMSG_ALIGN(header->nlmsg_len));
    header = nlmsg_next(header);
  }

  if (!warned_) {
    warned_ = true;
    Log::warn("generic netlink family {} not found (module not loaded?)",
              kFamilyName);
  }
  return std::nullopt;
}

bool NetlinkClient::ensure_connected() {
  if (socket_.valid())
    return true;

  const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
  if (fd < 0) {
    Log::warn("socket: {}", std::strerror(errno));
    return false;
  }

  sockaddr_nl address{};
  address.nl_family = AF_NETLINK;
  if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
    Log::warn("bind: {}", std::strerror(errno));
    ::close(fd);
    return false;
  }

  /*
   * Both directions need a deadline. If the module is unloaded between our
   * request and the reply there is nothing to receive, and without one the
   * helper would sit in recvmsg() forever: that is the "cannot connect after
   * rmmod/insmod" symptom.
   */
  timeval deadline{.tv_sec = 0, .tv_usec = 500'000};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));

  socket_.reset(fd);
  return true;
}

void NetlinkClient::note_reachable() {
  if (!warned_)
    return;
  warned_ = false;
  Log::info("kernel side reachable again");
}

bool NetlinkClient::push(std::span<const Pair> pairs) {
  /* Every policy goes up in pages: one message per page, then a commit that the
   * kernel checks against the total and the CRC before it switches. A policy
   * that arrives half way never takes effect. */
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (send_paged(pairs)) {
      note_reachable();
      return true;
    }
    family_.reset();
    socket_.reset();
  }
  if (!warned_) {
    warned_ = true;
    Log::warn("kernel side unreachable, keeping the previous policy");
    report_status("kernel unreachable");
  }
  return false;
}

std::optional<kaux_status> NetlinkClient::status() {
  if (!ensure_connected())
    return std::nullopt;
  if (!family_) {
    const auto resolved = resolve_family();
    if (!resolved)
      return std::nullopt;
    family_ = resolved;
  }

  Buffer request{};
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN), std::byte{0});
  auto *nlh = request.nlmsg();
  nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  nlh->nlmsg_type = *family_;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_seq = ++seq_;
  request.genlmsg()->cmd = KAUX_CMD_STATUS;
  request.genlmsg()->version = KAUX_FAMILY_VERSION;

  std::vector<std::byte> reply(kReplySize);
  unsupported_ = false;
  if (!exchange(std::span{request.bytes}.first(nlh->nlmsg_len), reply)) {
    if (unsupported_)
      Log::warn("the loaded module does not know KAUX_CMD_STATUS; it is older "
                "than this tool (a reboot loads the new one)");
    return std::nullopt;
  }

  const auto view = std::span<const std::byte>(reply.data(), reply_bytes_);
  int left = static_cast<int>(view.size());
  for (const std::byte *cursor = view.data();
       nlmsg_ok(reinterpret_cast<const nlmsghdr *>(cursor), left);) {
    const auto *header = reinterpret_cast<const nlmsghdr *>(cursor);
    const int step = static_cast<int>(NLMSG_ALIGN(header->nlmsg_len));
    if (header->nlmsg_type != NLMSG_ERROR && header->nlmsg_seq == seq_) {
      const auto *genl =
          reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
      int attr_left = static_cast<int>(header->nlmsg_len) -
                      static_cast<int>(NLMSG_LENGTH(GENL_HDRLEN));
      const auto *attr = reinterpret_cast<const nlattr *>(
          reinterpret_cast<const std::byte *>(genl) + GENL_HDRLEN);
      for (; nlattr_ok(attr, attr_left); attr = nlattr_next(attr)) {
        const int alen = static_cast<int>(attr->nla_len) - NLA_HDRLEN;
        attr_left -= static_cast<int>(NLA_ALIGN(attr->nla_len));
        if (attr->nla_type != KAUX_ATTR_STATUS)
          continue;
        if (alen != static_cast<int>(sizeof(kaux_status))) {
          Log::warn("status of {} byte(s), expected {}", alen,
                    sizeof(kaux_status));
          return std::nullopt;
        }
        kaux_status st{};
        std::memcpy(&st, reinterpret_cast<const std::byte *>(attr) + NLA_HDRLEN,
                    sizeof(st));
        if (st.magic != KAUX_STATUS_MAGIC || st.size != sizeof(st) ||
            st.version != KAUX_FAMILY_VERSION) {
          Log::warn("status does not look like ours (magic {:x}, size {})",
                    st.magic, st.size);
          return std::nullopt;
        }
        return st;
      }
      break;
    }
    left -= step;
    cursor += step;
  }
  return std::nullopt;
}

bool NetlinkClient::send_command(std::uint8_t cmd,
                                 std::span<const std::byte> blob) {
  if (!ensure_connected())
    return false;

  if (!family_) {
    const auto resolved = resolve_family();
    if (!resolved)
      return false;
    family_ = resolved;
  }

  Buffer request{};
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN) +
                           NLA_ALIGN(NLA_HDRLEN + blob.size()),
                       std::byte{0});

  auto *nlh = request.nlmsg();
  nlh->nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN + NLA_HDRLEN + static_cast<int>(blob.size()));
  nlh->nlmsg_type = *family_;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = ++seq_;

  auto *genl = request.genlmsg();
  genl->cmd = cmd;
  genl->version = KAUX_FAMILY_VERSION;

  auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(genl) +
                                          GENL_HDRLEN);
  attr->nla_type = KAUX_ATTR_BLOB;
  attr->nla_len = NLA_HDRLEN + static_cast<int>(blob.size());
  std::memcpy(reinterpret_cast<std::byte *>(attr) + NLA_HDRLEN, blob.data(),
              blob.size());

  std::vector<std::byte> reply(kReplySize);
  return exchange(std::span{request.bytes}.first(nlh->nlmsg_len), reply);
}

bool NetlinkClient::send_paged(std::span<const Pair> pairs) {
  /* The published staging protocol requires a nonempty blob. A reserved
   * system-UID pair is discarded by policy_apply, so it replaces the current
   * policy with an empty one without changing the kernel wire protocol. */
  const Pair empty_policy{0, 0};
  if (pairs.empty())
    pairs = std::span<const Pair>(&empty_policy, 1);
  const auto total = static_cast<std::uint32_t>(pairs.size());

  if (!send_command(KAUX_CMD_STAGE_BEGIN,
                    begin_payload(KAUX_KIND_POLICY, total * 8u, crc32(pairs))))
    return false;

  for (std::size_t sent = 0; sent < pairs.size();) {
    const std::size_t n = std::min(kPagePairs, pairs.size() - sent);

    if (!send_command(KAUX_CMD_STAGE_CHUNK,
                      page_payload(static_cast<std::uint32_t>(sent),
                                   pairs.subspan(sent, n))))
      return false; /* the kernel never saw a commit: the live policy stays */
    sent += n;
  }

  return send_command(KAUX_CMD_STAGE_COMMIT, {});
}

bool NetlinkClient::send_staged(std::uint32_t kind,
                                std::span<const std::byte> bytes) {
  if (!send_command(KAUX_CMD_STAGE_BEGIN,
                    begin_payload(kind,
                                  static_cast<std::uint32_t>(bytes.size()),
                                  crc32_bytes(bytes))))
    return false;

  for (std::size_t sent = 0; sent < bytes.size();) {
    const std::size_t n = std::min(kPageBytes, bytes.size() - sent);

    if (!send_command(KAUX_CMD_STAGE_CHUNK,
                      page_payload(static_cast<std::uint32_t>(sent),
                                   bytes.subspan(sent, n))))
      return false; /* the kernel never saw a commit: nothing was applied */
    sent += n;
  }

  return send_command(KAUX_CMD_STAGE_COMMIT, {});
}

bool NetlinkClient::push_apks(std::span<const ApkEntry> entries) {
  /*
   * The same upload the policy uses: the whole set is one blob, it goes up in
   * pages, and the commit applies it -- so the number of apps a device has is
   * not a number this side has to think about. The blob is the layout
   * src/policy.c reads: u32 n, n * (action, a, b, c), then the NUL-terminated
   * paths of the replacements.
   */
  std::size_t strings = 0;
  for (const auto &entry : entries)
    if (entry.action == 0)
      strings += entry.path.size() + 1;
  std::vector<std::byte> blob(sizeof(std::uint32_t) * (1 + 4 * entries.size()) +
                              strings);
  store_u32(blob, 0, static_cast<std::uint32_t>(entries.size()));
  std::size_t at = sizeof(std::uint32_t) * (1 + 4 * entries.size());
  for (std::size_t i = 0; i < entries.size(); ++i) {
    const std::size_t record = 4 + 16 * i;
    const ApkEntry &entry = entries[i];

    store_u32(blob, record + 0, entry.action);
    if (entry.action == 0) {
      store_u32(blob, record + 4, entry.uid);
      store_u32(blob, record + 8, static_cast<std::uint32_t>(at));
      store_u32(blob, record + 12,
                static_cast<std::uint32_t>(entry.path.size() + 1));
      std::memcpy(blob.data() + at, entry.path.c_str(), entry.path.size() + 1);
      at += entry.path.size() + 1;
    } else {
      store_u32(blob, record + 4, entry.dev);
      store_u32(blob, record + 8,
                static_cast<std::uint32_t>(entry.ino & 0xffffffffu));
      store_u32(blob, record + 12, static_cast<std::uint32_t>(entry.ino >> 32));
    }
  }

  if (send_staged(KAUX_KIND_APKS, blob)) {
    note_reachable();
    return true;
  }
  /* A lost COMMIT reply does not mean the inode operations did not run.
   * Let Syncer reconcile its per-inode ledger instead of blindly replaying
   * a delta that might retire a replacement it just installed. */
  family_.reset();
  socket_.reset();
  if (!warned_) {
    warned_ = true;
    Log::warn(
        "kernel side unreachable, caller apk update needs reconciliation");
    report_status("kernel unreachable");
  }
  return false;
}
} // namespace uidfake

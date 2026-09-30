/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kaux.h - the wire format of the netlink family the helper talks to.
 *
 * The module (src/netlink.c) and the tool (src/tools/netlink.cpp) both include
 * this file, so the two ends of the protocol cannot drift apart: what was a
 * comment on each side before is one definition here.
 *
 * Family version 3 has not been published, so this layout is the published one
 * and there is no earlier revision to stay compatible with.
 *
 * Everything is little endian and a multiple of four bytes long, so the
 * structures below are the wire image as they stand, with no packing:
 *
 *   KAUX_CMD_PING           -> ACK                    nothing, alive and version
 *   KAUX_CMD_STAGE_BEGIN    blob = struct kaux_begin  kind, byte count, crc32
 *   KAUX_CMD_STAGE_CHUNK    blob = u32 offset, u32 len, then len bytes
 *   KAUX_CMD_STAGE_COMMIT   -> ACK                    applies the staged blob
 *   KAUX_CMD_STATUS         -> reply: KAUX_ATTR_STATUS = struct kaux_status
 */
#ifndef UIDFAKE_KAUX_H
#define UIDFAKE_KAUX_H

#ifdef __cplusplus
#define KAUX_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define KAUX_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#define KAUX_FAMILY_NAME "kaux"
#define KAUX_FAMILY_VERSION 3u

/* One attribute carries the payload in either direction. */
enum {
	KAUX_ATTR_UNSPEC,
	KAUX_ATTR_BLOB, /* request payload */
	KAUX_ATTR_STATUS, /* struct kaux_status, on a STATUS reply */
	__KAUX_ATTR_MAX
};
#define KAUX_ATTR_MAX (__KAUX_ATTR_MAX - 1)

enum {
	KAUX_CMD_UNSPEC,
	KAUX_CMD_PING,
	KAUX_CMD_STAGE_BEGIN,
	KAUX_CMD_STAGE_CHUNK,
	KAUX_CMD_STAGE_COMMIT,
	KAUX_CMD_STATUS,
	__KAUX_CMD_MAX
};
#define KAUX_CMD_MAX (__KAUX_CMD_MAX - 1)

/* What a staged blob is. The policy is pairs of u32 (caller, target), the apk
 * set is records and the path bytes they name. */
#define KAUX_KIND_POLICY 0u
#define KAUX_KIND_APKS 1u
#define KAUX_KIND_MAX KAUX_KIND_APKS

struct kaux_begin {
	unsigned int kind;
	unsigned int bytes;
	unsigned int crc32;
};

/* What the module is doing, for the tool to show a user. Fixed size, so a
 * mismatch between the two ends is a checked error and not a misread. */
struct kaux_status {
	unsigned int magic; /* KAUX_STATUS_MAGIC, so a wrong blob is not read */
	unsigned int size; /* sizeof(struct kaux_status) */
	unsigned int version; /* KAUX_FAMILY_VERSION */
	/* KAUX_F_* below: which of the three registrations are in place */
	unsigned int flags;
	unsigned int native; /* entries hooked in sys_call_table */
	unsigned int native_expected;
	unsigned int compat; /* entries hooked in compat_sys_call_table */
	unsigned int compat_expected;
	/*
	 * The apk side, which is the other half of what the module does: the
	 * base.apk of every app that has rules has its open replaced, and a child
	 * is named from the one it opens. inodes is how many are held right now --
	 * it drops when an app is removed -- offered is what the last set carried
	 * (the uploads are differences), and failed is how many of those could not
	 * be put in place.
	 */
	unsigned int apk_inodes;
	unsigned int apk_offered;
	unsigned int apk_failed; /* of the last apply */
	unsigned int apk_failed_total; /* since the module was loaded */
	int lsm_state; /* KAUX_LSM_* */
	int lsm_error; /* errno, when lsm_state is KAUX_LSM_FAILED */
	int last_error; /* the most recent failure, 0 when there is none */
	unsigned int apk_updates; /* how many times the apk set was applied */
	/*
	 * The geometry this module was built for. The tool reads the running
	 * kernel's config (/proc/config.gz, which GKI ships) and compares: a device
	 * whose VA size differs puts the fixmap slot somewhere else, which the
	 * patcher proves before it writes, but a user is better served by a line
	 * that says so than by a hook that quietly is not there.
	 */
	unsigned int va_bits;
	unsigned int page_shift;
	char lsm_target[32]; /* the implementation the hook was taken from */
};
#define KAUX_STATUS_MAGIC 0x7875616bu /* "kaux" */

#define KAUX_F_NATIVE 0x1u
#define KAUX_F_COMPAT 0x2u
#define KAUX_F_SETUID 0x4u
#define KAUX_F_APKS 0x8u /* the last apk apply put every entry in place */
/* How the uid queries are answered: from a copy of find_user (one inline hook,
 * nothing in the syscall tables), or from the syscall tables. Neither set means
 * the queries are not answered at all. */
#define KAUX_F_PRIO_INLINE 0x10u
#define KAUX_F_PRIO_TABLES 0x20u

#define KAUX_LSM_NONE 0
#define KAUX_LSM_TAKEN 1
#define KAUX_LSM_FAILED 2
#define KAUX_LSM_FALLBACK 3

KAUX_STATIC_ASSERT(sizeof(struct kaux_status) == 104,
		   "kaux_status is the wire image");
KAUX_STATIC_ASSERT(sizeof(struct kaux_begin) == 12,
		   "kaux_begin is the wire image");

#endif /* UIDFAKE_KAUX_H */

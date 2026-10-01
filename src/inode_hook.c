// SPDX-License-Identifier: GPL-2.0
/*
 * inode_hook.c - naming a child from the apk it opens.
 *
 * The first file of its own code that an isolated child opens is what gives it
 * its identity. Every app that has rules has its base.apk's ->open replaced with
 * a copy of the inode's file_operations that differs in that one member and
 * carries the app id behind it, so the first open of its own code names the
 * whole thread group (tag.c keeps the record).
 *
 * Nothing is looked up on the open path and no reference to the inode is taken:
 * the copy is reached through the inode's own i_fop, so what is in that field is
 * the only thing the hook has to trust, and it checks for its own function
 * before reading anything behind it.
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#include "uidfake.h"

#ifndef UIDFAKE_HOST_TEST /* the host test has no inodes to shadow */
/* UF_SHADOW_BEGIN: scripts/extract_shadow.py lifts this block into the host test */

/*
	 * One record, and one table inside it, for one file: a record is never given to
	 * another file, because the inode it was made for may still point at that table
	 * (nothing is holding the inode, on purpose) and every open through it has to
	 * keep finding the operations it was made for. Records are freed at unload and
	 * not before.
	 */
/* Asked from the open path, declared here so the block carries its own
 * dependencies (the host test lifts it out of this file unchanged). */
bool uidfake_tag_pending_here(void);
void uidfake_tag_name(u32 app);

struct uf_shadow {
	const struct file_operations *orig_fops;
	struct file_operations fops; /* our copy: ->open is the only difference */
	int (*orig_open)(struct inode *, struct file *);
	u32 app;
	/* The numbers a helper can name this file by, so it can ask for it back
	 * after the path it came from is gone. */
	/* Kept so the table can be put back at unload: no inode is held, so the one
	 * behind this path has to be found again by name. */
	char *path;
	u32 dev;
	u64 ino;
	/*
	 * A record whose file is gone. It stays allocated -- a task may still be
	 * holding the pointer it read from that inode -- and is reused by the next
	 * replacement, so the array is bounded by UF_APK_MAX for the life of the
	 * module and the memory is freed at unload.
	 */
	bool parked;
};

/* cp_new_stat() hands userspace this encoding of s_dev; match it by hand. */
static u32 uf_encode_dev(dev_t s_dev)
{
	const u32 major = (u32)(s_dev >> 20) & 0xfffu;
	const u32 minor = (u32)s_dev & 0xfffffu;

	return (minor & 0xffu) | (major << 8) | ((minor & ~0xffu) << 12);
}

static struct uf_shadow *g_shadow[UF_APK_MAX]; /* installed, in use */
static u32 g_shadow_n;

static DEFINE_MUTEX(g_shadow_lock);
static int (*g_kern_path)(const char *name, unsigned int flags,
			  struct path *path);

static int uf_shadow_open(struct inode *inode, struct file *file)
{
	const struct file_operations *op = READ_ONCE(inode->i_fop);
	struct uf_shadow *s;

	/*
	 * What is in i_fop is what this call came through, and there is a record of
	 * ours behind it only when ->open is this function: a filesystem may have put
	 * its own table back since, and then the pointer is not ours to read.
	 */
	if (op == NULL)
		return 0;
	if (op->open != uf_shadow_open)
		return op->open != NULL ? op->open(inode, file) : 0;
	s = container_of(op, struct uf_shadow, fops);

	/*
	 * The hot path is this test: a load and a branch that falls through to the
	 * open the inode had before, as a tail call, so the fail path is a handful of
	 * instructions and nothing an attacker does can reach the other one -- only a
	 * task the framework is still setting up is pending.
	 */
	/*
	 * The numbers are checked as well, because an inode number is a number and not
	 * a name: a table of ours can outlive the file it was made for, and naming an
	 * app for a file that is not its own is the one thing that could come of that.
	 */
	if (s->dev != uf_encode_dev(inode->i_sb->s_dev) ||
	    s->ino != inode->i_ino)
		return s->orig_open ? s->orig_open(inode, file) : 0;
	if (uidfake_tag_pending_here())
		uidfake_tag_name(s->app);
	return s->orig_open ? s->orig_open(inode, file) : 0;
}

/* One table per file, told apart by the numbers a helper can name it by. */
static struct uf_shadow *shadow_find(u32 dev, u64 ino)
{
	u32 i;

	for (i = 0; i < g_shadow_n; i++)
		if (!g_shadow[i]->parked && g_shadow[i]->dev == dev &&
		    g_shadow[i]->ino == ino)
			return g_shadow[i];
	return NULL;
}

/* The record that owns a table, when a file already carries one of ours. */
__maybe_unused static struct uf_shadow *
shadow_owner(const struct file_operations *fop)
{
	u32 i;

	for (i = 0; i < g_shadow_n; i++)
		if (&g_shadow[i]->fops == fop)
			return g_shadow[i];
	return NULL;
}

__maybe_unused static int shadow_replace(const char *path, u32 uid)
{
	const u32 app = uid % 100000u;
	const struct file_operations *cur;
	struct uf_shadow *old, *s;
	struct inode *inode;
	struct path p;
	u32 dev;
	u64 ino;

	if (app < UF_APP_MIN || app >= UF_APP_MIN + UF_APP_SPAN)
		return -EINVAL;
	if (g_kern_path == NULL)
		g_kern_path = (void *)uidfake_lookup("kern_path");
	if (g_kern_path == NULL)
		return -ENOENT;
	if (g_kern_path(path, 0, &p))
		return -ENOENT;
	/*
	 * The inode is held for as long as it is read, and only for that: kern_path()
	 * pins the dentry, not the inode, and the package manager frees the inode it
	 * is replacing while the helper is still sending the new one -- reading its
	 * fields after that is a use-after-free, and an unlink is exactly that case
	 * (d_delete() takes the inode out of the dentry and drops it). Nothing keeps
	 * the reference past this call: what a record stores is the app to name and
	 * the table to put back, never a pointer to the inode itself.
	 */
	inode = igrab(d_backing_inode(p.dentry));
	path_put(&p);
	if (inode == NULL)
		return -ENOENT;
	/*
	 * The inode has to be finished before any of its fields is touched. The file
	 * systems set i_fop while the inode is still I_NEW (f2fs_iget(),
	 * erofs_iget()), so a write into that window races the file system's own --
	 * and an iput of such an inode takes iput_final()'s WARN_ON(I_NEW), which
	 * panics on a kernel that panics on warnings. igrab() has already refused an
	 * inode that is being freed (I_FREEING, I_WILL_FREE), and the extra reference
	 * it took is given back below, so no iput here is the last one.
	 */
	if (inode->i_state & I_NEW) {
		iput(inode);
		return -EAGAIN;
	}
	cur = READ_ONCE(inode->i_fop);
	if (cur == NULL) {
		iput(inode);
		return -EINVAL;
	}
	dev = uf_encode_dev(inode->i_sb->s_dev);
	ino = inode->i_ino;
	if (shadow_find(dev, ino) != NULL) {
		iput(inode);
		return 0; /* already replaced */
	}
	if (g_shadow_n >= UF_APK_MAX) {
		static bool warned;

		iput(inode);
		if (!warned) {
			warned = true;
			pr_warn("uidfake: %u app apk(s) have been replaced and the rest cannot be named\n",
				g_shadow_n);
		}
		return -ENOSPC;
	}
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (s != NULL) {
		s->path = kstrdup(path, GFP_KERNEL);
		if (s->path == NULL) {
			kfree(s);
			s = NULL;
		}
	}
	if (s == NULL) {
		iput(inode);
		return -ENOMEM;
	}
	/*
	 * A file that already carries a table of ours: the helper drops an apk when its
	 * path goes away, and the same inode comes back when a reinstall brings it
	 * home. What the record has to keep is the *original* table of that file --
	 * storing what the inode carries now would make this module's own open the one
	 * to chain to, and the first open after that would call itself forever.
	 */
	old = shadow_owner(cur);
	s->orig_fops = old ? old->orig_fops : cur;
	s->orig_open = old ? old->orig_open : cur->open;
	s->fops = *s->orig_fops;
	s->fops.open = uf_shadow_open;
	/*
	 * The copy is this module's memory and it is what every later open of this
	 * file goes through (VFS: f->f_op = fops_get(inode->i_fop)), so naming this
	 * module as its owner is what makes that a reference: the module cannot be
	 * unloaded while a file opened this way is still open, which is also what
	 * makes giving the records back at unload safe. The filesystem's own owner is
	 * not copied -- it is alive anyway, the inode is its own.
	 */
	s->fops.owner = THIS_MODULE;
	s->app = app - UF_APP_MIN;
	s->dev = dev;
	s->ino = ino;
	s->parked = false;
	WRITE_ONCE(inode->i_fop, &s->fops);
	g_shadow[g_shadow_n++] = s;
	iput(inode);
	return 0;
}

__maybe_unused static void shadow_drop_id(u32 dev, u64 ino)
{
	struct uf_shadow *s = NULL;
	u32 i;

	for (i = 0; i < g_shadow_n; i++)
		if (g_shadow[i]->dev == dev && g_shadow[i]->ino == ino)
			s = g_shadow[i];
	if (s == NULL)
		return;
	/*
	 * Only our own table changes here: that inode is the package manager's and it
	 * is on its way out -- the file is gone, which is why the helper sent this --
	 * so its i_fop is left alone. The record is parked, and parked is final: the
	 * table belongs to that one file for the rest of the module's life, because the
	 * inode may still be read from and every open through it has to keep finding
	 * the operations it was made for. A file that comes back -- even at the same
	 * inode number -- is given a table of its own.
	 */
	s->parked = true;
}

int uidfake_apk_apply(const u32 *blob, u32 len)
{
	const u32 n = blob[0];
	const u8 *bytes = (const u8 *)blob;
	u32 i, replaced = 0, dropped = 0, failed = 0;

	if (n > UF_APK_MAX || len < 4u + 16ull * n)
		return -EINVAL;
	/*
	 * Read-only pass, on purpose: it resolves the same paths the replacement
	 * would and prints what the package manager's inode looks like from here,
	 * but it writes nothing and takes no reference. That answers, in one boot,
	 * whether the inode is still I_NEW when this runs, whether its open is still
	 * the file system's, and which directory the path landed in.
	 */
	pr_info("uidfake: %u entr(ies) offered\n", n);
	for (i = 0; i < n && i < 8u; i++) {
		const u32 *e = &blob[1 + 4u * i];
		struct inode *inode;
		struct path p;
		const char *path;

		if (e[0] != 0u || e[3] == 0u || e[2] < 4u ||
		    (unsigned long long)e[2] + e[3] > len ||
		    bytes[e[2] + e[3] - 1u] != '\0')
			continue;
		path = (const char *)(bytes + e[2]);
		if (g_kern_path == NULL)
			g_kern_path = (void *)uidfake_lookup("kern_path");
		if (g_kern_path == NULL || g_kern_path(path, 0, &p))
			continue;
		/* the same reference the replacement takes: reading an inode the
		 * package manager has already let go of is a use-after-free even in a
		 * diagnostic */
		inode = igrab(d_backing_inode(p.dentry));
		path_put(&p);
		if (inode != NULL && UF_DEBUG_ON())
			pr_info("uidfake: apk probe %s: state=%#lx new=%d count=%d dev=%u ino=%lu size=%lld\n",
				path, (unsigned long)inode->i_state,
				!!(inode->i_state & I_NEW),
				atomic_read(&inode->i_count),
				(unsigned int)uf_encode_dev(inode->i_sb->s_dev),
				(unsigned long)inode->i_ino,
				(long long)i_size_read(inode));
		if (inode != NULL)
			iput(inode);
	}
	mutex_lock(&g_shadow_lock);
	for (i = 0; i < n; i++) {
		const u32 *e = &blob[1 + 4u * i];
		const u32 action = e[0];

		if (UF_DEBUG_ON())
			pr_info("uidfake: apk entry %u: action %u a=%u b=%u c=%u\n",
				i, action, e[1], e[2], e[3]);
		if (action == 0u) {
			const u32 uid = e[1], off = e[2], size = e[3];
			const char *path;

			if (size == 0 || off < 4u || off + size > len ||
			    bytes[off + size - 1u] != '\0')
				continue;
			path = (const char *)(bytes + off);
			if (shadow_replace(path, uid) == 0)
				replaced++;
			else
				failed++;
		} else if (action == 1u) {
			/*
			 * Our own table is all this touches: the file is gone -- that is why the
			 * helper sent this -- and the inode that still points at our table
			 * belongs to the package manager, which is the one that reclaims it.
			 * Reaching into that inode from here is what took the kernel down on
			 * an install.
			 */
			shadow_drop_id(e[1], ((u64)e[3] << 32) | e[2]);
			dropped++;
		} else {
			failed++;
		}
	}
	mutex_unlock(&g_shadow_lock);
	pr_info("uidfake: %u apk inode(s) replaced, %u put back, %u of %u entr(ies) failed\n",
		replaced, dropped, failed, n);
	/*
	 * What the status carries is how many inodes are held right now, so an apply
	 * that only carries one new app does not make it look as if that one were the
	 * whole set. offered is what this set carried; a failure counts against it.
	 */
	{
		u32 live = 0;

		/* counted from the table, not from the deltas of this call: a drop
		 * for an entry this kernel never had used to take the number below
		 * zero, and the status line then showed four billion inodes. */
		for (i = 0; i < g_shadow_n; i++)
			if (!g_shadow[i]->parked)
				live++;
		uidfake_status_set_apks(live, n, failed);
	}
	return 0;
}

/*
 * Put every table back, at unload. No inode is held anywhere, so the one behind
 * a record is found again from the path stored when it was replaced: the file
 * may be gone by now, or the path may point at a replacement, and then there is
 * nothing to put back -- a new inode has its own open, and it is either already
 * replaced or was never asked for.
 */
void uidfake_apk_remove(void)
{
	u32 i, unresolved = 0;

	mutex_lock(&g_shadow_lock);
	for (i = 0; i < g_shadow_n; i++) {
		struct uf_shadow *s = g_shadow[i];
		struct inode *inode;
		struct path p;

		if (s->path == NULL)
			continue;
		if (g_kern_path == NULL)
			g_kern_path = (void *)uidfake_lookup("kern_path");
		if (g_kern_path == NULL || g_kern_path(s->path, 0, &p) != 0) {
			unresolved++;
			continue;
		}
		inode = igrab(d_backing_inode(p.dentry));
		path_put(&p);
		if (inode == NULL)
			continue;
		if (READ_ONCE(inode->i_fop) == &s->fops)
			WRITE_ONCE(inode->i_fop, s->orig_fops);
		iput(inode);
	}
	/*
	 * The records are this module's memory and the module is going away, so they
	 * are given back here -- parked ones included. Nothing else frees them: they
	 * outlive the files they were made for on purpose, so that no record is ever
	 * handed back while an inode may still point at its table.
	 *
	 * what can still reference one at this point: a file opened through it holds a
	 * reference on THIS_MODULE (the owner set in the copy), and module_exit runs
	 * only with that count at zero, so no such file is left open; an inode holds
	 * nothing by itself, and the ones still reachable by name were put back just
	 * above. A record counted as unresolved is a file the package manager moved or
	 * removed: its path is gone, so the only handle left on that inode is one a
	 * process already has -- and that is a file opened through the table, which is
	 * counted above.
	 */
	if (unresolved != 0)
		pr_info("uidfake: %u apk file(s) could not be found again at unload\n",
			unresolved);
	for (i = 0; i < g_shadow_n; i++) {
		kfree(g_shadow[i]->path);
		kfree(g_shadow[i]);
		g_shadow[i] = NULL;
	}
	g_shadow_n = 0;
	mutex_unlock(&g_shadow_lock);
}
/* UF_SHADOW_END */
#endif

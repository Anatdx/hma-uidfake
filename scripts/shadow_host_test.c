/* Host test for the inode shadow records of src/policy.c.
 *
 * The block is kernel-only (it needs inodes), so scripts/extract_shadow.py lifts it
 * out of the file and this drives it. What the scenarios pin down is what went
 * wrong in it: an inode the package manager let go of while its fields were being
 * read, a table handed to a file it was not made for, an open that chained to
 * itself, and a record installed even though its path could not be stored. Run
 * under ASan on purpose -- three of those were use-after-free or type confusion,
 * which a plain run does not show.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* What the block expects from the kernel. */
#define UF_APK_MAX 16
#define UF_APP_MIN 10000u
#define UF_APP_SPAN 10000u
#define I_NEW 1u
#define I_FREEING 2u
#define I_WILL_FREE 4u
#define GFP_KERNEL 0u
#define __maybe_unused
#define __nocfi
#define DEFINE_MUTEX(x) int x
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define UF_DEBUG_ON() 0
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define atomic_read(p) (*(p))
#define i_size_read(p) 0LL

struct module;
struct inode;
struct file;

struct file_operations {
	struct module *owner;
	int (*open)(struct inode *, struct file *);
	int (*read_iter)(struct file *);
};

struct super_block {
	dev_t s_dev;
};

struct inode {
	const struct file_operations *i_fop;
	struct super_block *i_sb;
	unsigned long i_ino;
	unsigned long i_state;
	int i_count;
};

struct file {
	const struct file_operations *f_op;
};

struct dentry {
	struct inode *inode;
	struct dentry *d_parent;
	struct {
		const char *name;
	} d_name;
};

struct path {
	struct dentry *dentry;
};

#define d_backing_inode(d) ((d)->inode)

/* The module a table belongs to: fops_get() takes a reference on its owner, and the
 * block has to name this module as the owner of the copy it installs. */
static int g_module;
#define THIS_MODULE ((struct module *)&g_module)

static bool g_kstrdup_fails;

static void *uf_kzalloc(size_t bytes)
{
	return calloc(1, bytes);
}

static char *uf_kstrdup(const char *s)
{
	return g_kstrdup_fails ? NULL : strdup(s);
}

#define kzalloc(bytes, flags) uf_kzalloc(bytes)
#define kfree(p) free(p)
#define kstrdup(s, flags) uf_kstrdup(s)

/* igrab() refuses an inode that is being freed -- that is what makes reading its
 * fields safe -- and iput() gives the reference back; the last one evicts the
 * inode the way the kernel does. */
static struct inode *igrab(struct inode *inode)
{
	if (inode == NULL || (inode->i_state & (I_FREEING | I_WILL_FREE)))
		return NULL;
	inode->i_count++;
	return inode;
}

static void iput(struct inode *inode)
{
	if (inode == NULL)
		return;
	if (--inode->i_count == 0)
		free(inode);
}

static int open_a(struct inode *inode, struct file *file);
static int open_b(struct inode *inode, struct file *file);
static int read_a(struct file *file)
{
	(void)file;
	return 111;
}
static int read_b(struct file *file)
{
	(void)file;
	return 222;
}

static const struct file_operations ops_a = { .open = open_a,
					      .read_iter = read_a };
static const struct file_operations ops_b = { .open = open_b,
					      .read_iter = read_b };

static struct inode *g_a;
static struct inode *g_b;
static struct dentry d_a;
static struct dentry d_b;
static struct super_block g_sb = { .s_dev = 1 };

static int open_a(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	return 11;
}

static int open_b(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	return 22;
}

static const char *kApkA = "/data/app/~~a/com.a/base.apk";
static const char *kApkB = "/data/app/~~b/com.b/base.apk";

static int fake_kern_path(const char *name, unsigned int flags, struct path *p)
{
	(void)flags;
	if (!strcmp(name, kApkA))
		p->dentry = &d_a;
	else if (!strcmp(name, kApkB))
		p->dentry = &d_b;
	else
		return -ENOENT;
	if (p->dentry->inode == NULL)
		return -ENOENT;
	p->dentry->inode->i_count++; /* the reference the dentry holds for us */
	return 0;
}

/* What a dentry reference keeps: d_delete() takes the inode out of the dentry and
 * lets it go, and that is the case the block has to survive. */
static void path_put(struct path *p)
{
	iput(p->dentry->inode);
}

static unsigned long uidfake_lookup(const char *name)
{
	(void)name;
	return (unsigned long)fake_kern_path;
}

static void uidfake_status_set_apks(unsigned int inodes, unsigned int offered,
				    unsigned int failed)
{
	(void)inodes;
	(void)offered;
	(void)failed;
}

/* count is the number of references the inode starts with: the lookup takes one of
 * its own, and anything above that stands for whoever else still holds it (the
 * package manager's inode cache). */
static struct inode *new_inode(const struct file_operations *ops,
			       unsigned long ino, int count)
{
	struct inode *inode = uf_kzalloc(sizeof(*inode));

	assert(inode != NULL);
	inode->i_fop = ops;
	inode->i_sb = &g_sb;
	inode->i_ino = ino;
	inode->i_count = count;
	return inode;
}

/* held = how many references the file has besides the one the lookup takes. */
static void setup_a(int held)
{
	g_a = new_inode(&ops_a, 100, 1 + held);
	d_a.inode = g_a;
}

static void setup_b(int held)
{
	g_b = new_inode(&ops_b, 200, 1 + held);
	d_b.inode = g_b;
}

#include "shadow_block.inc"

/* The block asks the tag record two questions (see tag.c): nothing here is
 * waiting for a name, and the name itself is what the test that follows checks
 * by hand rather than through the hook. */
bool uidfake_tag_pending_here(void)
{
	return false;
}

void uidfake_tag_name(u32 app)
{
	(void)app;
}

/* A file opened through a table, the way VFS does it. */
static int open_through(const struct file_operations *fops, struct inode *inode)
{
	struct file file = { .f_op = fops };

	return fops->open(inode, &file);
}

/* The inode the lookup hands over is the one the package manager evicts while its
 * fields are still being read: without a reference of our own that read is a
 * use-after-free, which is what the sanitizer is here for. The record still has to
 * end up installed and complete. */
static void scenario_early_put(void)
{
	setup_a(0);
	assert(shadow_replace(kApkA, 10123) == 0);
	assert(g_shadow_n == 1);
	assert(!g_shadow[0]->parked);
	assert(g_shadow[0]->dev == uf_encode_dev(g_sb.s_dev));
	assert(g_shadow[0]->ino == 100);
	assert(g_shadow[0]->app == 123);
	assert(g_shadow[0]->fops.owner == THIS_MODULE);
	assert(g_shadow[0]->orig_open == open_a);
}

/* A table belongs to the file it was made for: the second replacement must not
 * touch the first one's, or an inode that still points at it dispatches into
 * another filesystem's operations. */
static void scenario_no_reuse(void)
{
	setup_a(1);
	setup_b(0);
	assert(shadow_replace(kApkA, 10123) == 0);
	shadow_drop_id(uf_encode_dev(g_sb.s_dev), 100);
	assert(g_shadow[0]->parked);

	assert(shadow_replace(kApkB, 10456) == 0);
	assert(g_shadow_n == 2);
	assert(!g_shadow[1]->parked);
	assert(g_shadow[1]->ino == 200);
	assert(open_through(&g_shadow[1]->fops, g_b) == 22);

	/* the old file still finds the operations it was made for */
	assert(g_shadow[0]->orig_open == open_a);
	assert(open_through(&g_shadow[0]->fops, g_a) == 11);
	assert(g_shadow[0]->fops.read_iter(NULL) == 111);
}

/* A file that comes back after being dropped is given a table of its own, and that
 * table has to chain to the file's own open -- chaining to this module's would call
 * itself until the stack is gone. */
static void scenario_readd(void)
{
	setup_a(1);
	assert(shadow_replace(kApkA, 10123) == 0);
	shadow_drop_id(uf_encode_dev(g_sb.s_dev), 100);
	assert(shadow_replace(kApkA, 10123) == 0);
	assert(g_shadow_n == 2);
	assert(g_shadow[1]->orig_open != uf_shadow_open);
	assert(g_shadow[1]->orig_open == open_a);
	assert(open_through(&g_shadow[1]->fops, g_a) == 11);
}

/* A record whose path cannot be stored is not installed: the write would leave an
 * inode pointing at a table that no path can find again at unload. */
static void scenario_kstrdup_fail(void)
{
	setup_a(1);
	g_kstrdup_fails = true;
	assert(shadow_replace(kApkA, 10123) == -ENOMEM);
	assert(g_shadow_n == 0);
	assert(g_a->i_fop == &ops_a);
}

/* Unloading puts every file back and gives the records away. */
static void scenario_remove(void)
{
	setup_a(1);
	assert(shadow_replace(kApkA, 10123) == 0);
	assert(g_a->i_fop == &g_shadow[0]->fops);
	uidfake_apk_remove();
	assert(g_shadow_n == 0);
	assert(g_a->i_fop == &ops_a);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr,
			"usage: %s <early-put|no-reuse|readd|kstrdup-fail|remove>\n",
			argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "early-put"))
		scenario_early_put();
	else if (!strcmp(argv[1], "no-reuse"))
		scenario_no_reuse();
	else if (!strcmp(argv[1], "readd"))
		scenario_readd();
	else if (!strcmp(argv[1], "kstrdup-fail"))
		scenario_kstrdup_fail();
	else if (!strcmp(argv[1], "remove"))
		scenario_remove();
	else
		return 2;
	printf("shadow: %s PASS\n", argv[1]);
	return 0;
}

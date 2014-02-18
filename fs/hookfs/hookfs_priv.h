/*
 * Copyright (c) 1998-2013 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2013 Stony Brook University
 * Copyright (c) 2003-2013 The Research Foundation of SUNY
 * Copyright (c) 2013-2014 Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _HOOKFS_PRIV_H_
#define _HOOKFS_PRIV_H_

#include <linux/dcache.h>
#include <linux/hookfs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/kref.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/uaccess.h>

/* the file system name */
#define HOOKFS_NAME "hookfs"

/* hookfs root inode number */
#define HOOKFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* operations vectors defined in specific files */
extern const struct file_operations hookfs_main_fops;
extern const struct file_operations hookfs_dir_fops;
extern const struct inode_operations hookfs_main_iops;
extern const struct inode_operations hookfs_dir_iops;
extern const struct inode_operations hookfs_symlink_iops;
extern const struct super_operations hookfs_sops;
extern const struct dentry_operations hookfs_dops;
extern const struct address_space_operations hookfs_aops;
extern const struct address_space_operations hookfs_dummy_aops;
extern const struct vm_operations_struct hookfs_vm_ops;

extern int hookfs_init_inode_cache(void);
extern void hookfs_destroy_inode_cache(void);
extern int hookfs_init_dentry_cache(void);
extern void hookfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern int init_lower_nd(struct nameidata *nd, unsigned int flags);
extern struct dentry *hookfs_lookup(struct inode *dir,
    struct dentry *dentry, unsigned int flags);
extern struct inode *hookfs_iget(struct super_block *sb,
    struct inode *lower_inode);
extern int hookfs_interpose(struct dentry *dentry, struct super_block *sb,
    struct path *lower_path);

extern void hookfs_release_hook(struct kref *);


/* file private data */
struct hookfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* hookfs inode data in memory */
struct hookfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

struct hookfs_hook_int {
	uint64_t hi_id;
	struct kref hi_ref;		/* keeps hi_fn and hi_data alive. Use with RCU. */
	struct list_head hi_node;
	void *hi_data;
	void (*hi_release)(void *, uint64_t);	/* called when hi_ref drops to 0 */
	union {
		void (*pre_read)(void *, struct file **, char **, size_t *,
		    loff_t **);
		ssize_t (*post_read)(ssize_t, void *, struct file *, char *,
		    size_t, loff_t *);
	} __rcu hi_fn;
};

/* hookfs dentry data in memory */
struct hookfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

struct hookfs_put_super_cb {
	uint64_t cb_id;
	void (*cb_put)(struct super_block *);
	struct list_head cb_node;
};

/* hookfs super-block data in memory */
struct hookfs_sb_info {
	struct super_block *lower_sb;

	struct mutex write_lock;	/* fields below are write protected by this mutex */
	uint64_t last_id;
	struct list_head put_super_callbacks;
	struct list_head hooks[HOOKFS_HOOK_MODES];
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * hookfs_inode_info structure, hookfs_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct hookfs_inode_info *hookfs_I(
    const struct inode *inode)
{
	return container_of(inode, struct hookfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define HOOKFS_D(dent) ((struct hookfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define HOOKFS_SB(super) ((struct hookfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define HOOKFS_F(file) ((struct hookfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *hookfs_lower_file(const struct file *f)
{
	return HOOKFS_F(f)->lower_file;
}

static inline void hookfs_set_lower_file(struct file *f, struct file *val)
{
	HOOKFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *hookfs_lower_inode(const struct inode *i)
{
	return hookfs_I(i)->lower_inode;
}

static inline void hookfs_set_lower_inode(struct inode *i,
    struct inode *val)
{
	hookfs_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *hookfs_lower_super(
    const struct super_block *sb)
{
	return HOOKFS_SB(sb)->lower_sb;
}

static inline void hookfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	HOOKFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void hookfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&HOOKFS_D(dent)->lock);
	pathcpy(lower_path, &HOOKFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&HOOKFS_D(dent)->lock);
}
static inline void hookfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
}
static inline void hookfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&HOOKFS_D(dent)->lock);
	pathcpy(&HOOKFS_D(dent)->lower_path, lower_path);
	spin_unlock(&HOOKFS_D(dent)->lock);
}
static inline void hookfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&HOOKFS_D(dent)->lock);
	HOOKFS_D(dent)->lower_path.dentry = NULL;
	HOOKFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&HOOKFS_D(dent)->lock);
}
static inline void hookfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&HOOKFS_D(dent)->lock);
	pathcpy(&lower_path, &HOOKFS_D(dent)->lower_path);
	HOOKFS_D(dent)->lower_path.dentry = NULL;
	HOOKFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&HOOKFS_D(dent)->lock);
	path_put(&lower_path);
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

/* dentry private data allocation and deallocation */
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);

#endif	/* _HOOKFS_PRIV_H_ */

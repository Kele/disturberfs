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

#include "hookfs_priv.h"

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *hookfs_inode_cachep;

/* final actions when unmounting a file system */
static void hookfs_put_super(struct super_block *sb)
{
	struct hookfs_sb_info *sbi;
	struct super_block *s;
	struct hookfs_hook_int *hi;
	struct hookfs_put_super_cb *cb;

	sbi = HOOKFS_SB(sb);
	if (sbi == NULL)
		return;

	mutex_lock(&sbi->write_lock);
	list_for_each_entry(cb, &sbi->put_super_callbacks, cb_node) {
		(*cb->cb_put)(sb);
	}
	while (!list_empty(&sbi->put_super_callbacks)) {
		cb = list_first_entry(&sbi->put_super_callbacks, struct hookfs_put_super_cb,
		    cb_node);
		list_del(&cb->cb_node);
		kfree(cb);
	}

	/*
	 * XXX: It is not safe to call hookfs_{install,remove}_hook() anymore.
	 *
	 * At this point clients of hookfs should have cleaned up everything on
	 * their side, so we just free our structures.
	 */
	for (int i = 0; i < ARRAY_SIZE(sbi->hooks); i++) {
		while ((hi = list_first_or_null_rcu(&sbi->hooks[i],
		    struct hookfs_hook_int, hi_node)) != NULL) {
			list_del_rcu(&hi->hi_node);
			kfree(hi);
		}
	}
	mutex_unlock(&sbi->write_lock);

	/* decrement lower super references */
	s = hookfs_lower_super(sb);
	hookfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);
	mutex_destroy(&sbi->write_lock);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

static int hookfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	hookfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	hookfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = HOOKFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int hookfs_remount_fs(struct super_block *sb, int *flags,
	char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "hookfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void hookfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = hookfs_lower_inode(inode);
	hookfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *hookfs_alloc_inode(struct super_block *sb)
{
	struct hookfs_inode_info *i;

	i = kmem_cache_alloc(hookfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct hookfs_inode_info, vfs_inode));

	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void hookfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(hookfs_inode_cachep, hookfs_I(inode));
}

/* hookfs inode cache constructor */
static void init_once(void *obj)
{
	struct hookfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int hookfs_init_inode_cache(void)
{
	int err = 0;

	hookfs_inode_cachep =
		kmem_cache_create("hookfs_inode_cache",
				  sizeof(struct hookfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!hookfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* hookfs inode cache destructor */
void hookfs_destroy_inode_cache(void)
{
	if (hookfs_inode_cachep)
		kmem_cache_destroy(hookfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void hookfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = hookfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

const struct super_operations hookfs_sops = {
	.put_super	= hookfs_put_super,
	.statfs		= hookfs_statfs,
	.remount_fs	= hookfs_remount_fs,
	.evict_inode	= hookfs_evict_inode,
	.umount_begin	= hookfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= hookfs_alloc_inode,
	.destroy_inode	= hookfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};

/*
 * Copyright (c) 2013-2014 Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>

#include "hookfs_priv.h"
/*
 * There is no need to lock the hookfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int hookfs_read_super(struct super_block *sb, void *raw_data,
	int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "hookfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"hookfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct hookfs_sb_info), GFP_KERNEL);
	if (!HOOKFS_SB(sb)) {
		printk(KERN_CRIT "hookfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* initialize HOOKFS_SB(sb) */
	mutex_init(&HOOKFS_SB(sb)->write_lock);
	for (int i = 0; i < ARRAY_SIZE(HOOKFS_SB(sb)->hooks); i++)
		INIT_LIST_HEAD(&HOOKFS_SB(sb)->hooks[i]);

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	hookfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &hookfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = hookfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &hookfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	hookfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "hookfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	mutex_destroy(&HOOKFS_SB(sb)->write_lock);
	kfree(HOOKFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct dentry *hookfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;

	return mount_nodev(fs_type, flags, lower_path_name,
			   hookfs_read_super);
}

static struct file_system_type hookfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= HOOKFS_NAME,
	.mount		= hookfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_hookfs_fs(void)
{
	int err;

	pr_info("Registering hookfs " HOOKFS_VERSION "\n");

	err = hookfs_init_inode_cache();
	if (err)
		goto out;
	err = hookfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&hookfs_fs_type);
out:
	if (err) {
		hookfs_destroy_inode_cache();
		hookfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_hookfs_fs(void)
{
	hookfs_destroy_inode_cache();
	hookfs_destroy_dentry_cache();
	unregister_filesystem(&hookfs_fs_type);
	pr_info("Completed hookfs module unload\n");
}

MODULE_AUTHOR("Damian Bogel");
MODULE_DESCRIPTION("hookfs " HOOKFS_VERSION);
MODULE_LICENSE("GPL");

module_init(init_hookfs_fs);
module_exit(exit_hookfs_fs);

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

/* The dentry cache is just so we have properly sized dentries */
struct kmem_cache *hookfs_dentry_cachep;

int hookfs_init_dentry_cache(void)
{
	hookfs_dentry_cachep =
		kmem_cache_create("hookfs_dentry",
				  sizeof(struct hookfs_dentry_info),
				  0, SLAB_RECLAIM_ACCOUNT, NULL);

	return hookfs_dentry_cachep ? 0 : -ENOMEM;
}

void hookfs_destroy_dentry_cache(void)
{
	if (hookfs_dentry_cachep)
		kmem_cache_destroy(hookfs_dentry_cachep);
}

/*
 * Initialize a nameidata structure (the intent part) we can pass to a lower
 * file system.  Returns 0 on success or -error (only -ENOMEM possible).
 */
int init_lower_nd(struct nameidata *nd, unsigned int flags)
{
	int err = 0;

	memset(nd, 0, sizeof(struct nameidata));
	if (!flags)
		goto out;

	switch (flags) {
	case LOOKUP_CREATE:
	case LOOKUP_OPEN:
		nd->flags = flags;
		break;
	default:
		/* We should never get here, for now */
		pr_debug("hookfs: unknown nameidata flag 0x%x\n", flags);
		BUG();
		break;
	}

out:
	return err;
}

static int hookfs_inode_test(struct inode *inode,
	void *candidate_lower_inode)
{
	struct inode *current_lower_inode = hookfs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int hookfs_inode_set(struct inode *inode, void *lower_inode)
{
	/* we do actual inode initialization in hookfs_iget */
	return 0;
}

struct inode *hookfs_iget(struct super_block *sb,
	struct inode *lower_inode)
{
	struct hookfs_inode_info *info;
	struct inode *inode; /* the new inode to return */
	int err;

	inode = iget5_locked(sb, /* our superblock */
	     /*
	      * hashval: we use inode number, but we can
	      * also use "(unsigned long)lower_inode"
	      * instead.
	      */
	     lower_inode->i_ino, /* hashval */
	     hookfs_inode_test,	/* inode comparison function */
	     hookfs_inode_set, /* inode init function */
	     lower_inode); /* data passed to test+set fxns */

	if (!inode) {
		err = -EACCES;
		iput(lower_inode);
		return ERR_PTR(err);
	}
	/* if found a cached inode, then just return it */
	if (!(inode->i_state & I_NEW))
		return inode;

	/* initialize new inode */
	info = hookfs_I(inode);

	inode->i_ino = lower_inode->i_ino;
	if (!igrab(lower_inode)) {
		err = -ESTALE;
		return ERR_PTR(err);
	}
	hookfs_set_lower_inode(inode, lower_inode);

	inode->i_version++;

	/* use different set of inode ops for symlinks & directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &hookfs_dir_iops;
	else if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &hookfs_symlink_iops;
	else
		inode->i_op = &hookfs_main_iops;

	/* use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &hookfs_dir_fops;
	else
		inode->i_fop = &hookfs_main_fops;

	inode->i_mapping->a_ops = &hookfs_aops;

	inode->i_atime.tv_sec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = 0;
	inode->i_ctime.tv_nsec = 0;

	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
	    S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
		    lower_inode->i_rdev);

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	unlock_new_inode(inode);
	return inode;
}

/*
 * Connect a hookfs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: hookfs's dentry which interposes on lower one
 * @sb: hookfs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int hookfs_interpose(struct dentry *dentry, struct super_block *sb,
		     struct path *lower_path)
{
	int err = 0;
	struct inode *inode;
	struct inode *lower_inode;
	struct super_block *lower_sb;

	lower_inode = lower_path->dentry->d_inode;
	lower_sb = hookfs_lower_super(sb);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		err = -EXDEV;
		goto out;
	}

	/*
	 * We allocate our new inode below by calling hookfs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* inherit lower inode number for hookfs's inode */
	inode = hookfs_iget(sb, lower_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_add(dentry, inode);
//	d_splice_alias(inode, dentry);

out:
	return err;
}

/*
 * Main driver function for hookfs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
static struct dentry *__hookfs_lookup(struct dentry *dentry,
				      unsigned int flags,
				      struct path *lower_parent_path)
{
	int err = 0;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry;
	const char *name;
	struct path lower_path;
	struct qstr this;

	/* must initialize dentry operations */
	d_set_d_op(dentry, &hookfs_dops);

	if (IS_ROOT(dentry))
		goto out;

	name = dentry->d_name.name;

	/* now start the actual lookup procedure */
	lower_dir_dentry = lower_parent_path->dentry;
	lower_dir_mnt = lower_parent_path->mnt;

	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, name, 0,
			      &lower_path);

	/* no error: handle positive dentries */
	if (!err) {
		hookfs_set_lower_path(dentry, &lower_path);
		err = hookfs_interpose(dentry, dentry->d_sb, &lower_path);
		if (err) /* path_put underlying path on error */
			hookfs_put_reset_lower_path(dentry);
		goto out;
	}

	/*
	 * We don't consider ENOENT an error, and we want to return a
	 * negative dentry.
	 */
	if (err && err != -ENOENT)
		goto out;

	/* instatiate a new negative dentry */
	this.name = name;
	this.len = strlen(name);
	this.hash = full_name_hash(this.name, this.len);
	lower_dentry = d_lookup(lower_dir_dentry, &this);
	if (lower_dentry)
		goto setup_lower;

	lower_dentry = d_alloc(lower_dir_dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_add(lower_dentry, NULL); /* instantiate and hash */

setup_lower:
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	hookfs_set_lower_path(dentry, &lower_path);

	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;

out:
	return ERR_PTR(err);
}

struct dentry *hookfs_lookup(struct inode *dir, struct dentry *dentry,
			     unsigned int flags)
{
	struct dentry *ret, *parent;
	struct path lower_parent_path;
	int err = 0;

	parent = dget_parent(dentry);

	hookfs_get_lower_path(parent, &lower_parent_path);

	/* allocate dentry private data.  We free it in ->d_release */
	err = new_dentry_private_data(dentry);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}

	ret = __hookfs_lookup(dentry, flags, &lower_parent_path);
	if (IS_ERR(ret))
		goto out;
	if (ret)
		dentry = ret;
	if (dentry->d_inode)
		fsstack_copy_attr_times(dentry->d_inode,
		    hookfs_lower_inode(dentry->d_inode));
	/* update parent directory's atime */
	fsstack_copy_attr_atime(parent->d_inode,
	    hookfs_lower_inode(parent->d_inode));

out:
	hookfs_put_lower_path(parent, &lower_parent_path);
	dput(parent);
	return ret;
}

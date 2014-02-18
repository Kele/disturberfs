/*
 * Copyright (c) 1998-2013 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2013 Stony Brook University
 * Copyright (c) 2003-2013 The Research Foundation of SUNY
 * Copyright (c) 2013      Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "hookfs_priv.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
static int hookfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct path lower_path;
	struct dentry *lower_dentry;
	int err = 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	hookfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;
	err = lower_dentry->d_op->d_revalidate(lower_dentry, flags);
out:
	hookfs_put_lower_path(dentry, &lower_path);
	return err;
}

static void hookfs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */
	hookfs_put_reset_lower_path(dentry);
	free_dentry_private_data(dentry);
}

extern struct kmem_cache *hookfs_dentry_cachep;

/* dentry private data allocation and deallocation */
int new_dentry_private_data(struct dentry *dentry)
{
	struct hookfs_dentry_info *info = HOOKFS_D(dentry);

	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(hookfs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}
void free_dentry_private_data(struct dentry *dentry)
{
	if (dentry == NULL || dentry->d_fsdata == NULL)
		return;

	kmem_cache_free(hookfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

const struct dentry_operations hookfs_dops = {
	.d_revalidate	= hookfs_d_revalidate,
	.d_release	= hookfs_d_release,
};

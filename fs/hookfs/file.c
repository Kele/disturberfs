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

static ssize_t hookfs_read(struct file *file, char __user *buf, size_t count,
    loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	struct hookfs_sb_info *sbinfo = HOOKFS_SB(dentry->d_sb);
	struct list_head *node;
	struct hookfs_hook_int *hi;

	lower_file = hookfs_lower_file(file);

	rcu_read_lock();
	hi = list_first_or_null_rcu(
	    &sbinfo->hooks[HOOKFS_MKMODE(HOOKFS_OP_READ, HOOKFS_TYPE_PRE)],
	    struct hookfs_hook_int, hi_node);
	if (hi != NULL)
		kref_get(&hi->hi_ref);
	rcu_read_unlock();

	while (hi != NULL) {
		(*hi->hi_fn.pre_read)(hi->hi_data, &lower_file, &buf, &count, &ppos);
		
		rcu_read_lock();
		kref_put(&hi->hi_ref, hookfs_release_hook);
		node = list_next_rcu(&hi->hi_node);
		if (node != NULL) {
			hi = list_entry_rcu(node, struct hookfs_hook_int, hi_node);
			kref_get(&hi->hi_ref);
		} else {
			hi = NULL;
		}
		rcu_read_unlock();
	}

	err = vfs_read(lower_file, buf, count, ppos);
	
	rcu_read_lock();
	hi = list_first_or_null_rcu(
	    &sbinfo->hooks[HOOKFS_MKMODE(HOOKFS_OP_READ, HOOKFS_TYPE_POST)],
	    struct hookfs_hook_int, hi_node);
	if (hi != NULL)
		kref_get(&hi->hi_ref);
	rcu_read_unlock();

	while (hi != NULL) {
		err = (*hi->hi_fn.post_read)(err, hi->hi_data, lower_file, buf, count, ppos);
		
		rcu_read_lock();
		kref_put(&hi->hi_ref, hookfs_release_hook);
		node = list_next_rcu(&hi->hi_node);
		if (node != NULL) {
			hi = list_entry_rcu(node, struct hookfs_hook_int, hi_node);
			kref_get(&hi->hi_ref);
		} else {
			hi = NULL;
		}
		rcu_read_unlock();
	}


	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

	return err;
}

static ssize_t hookfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = hookfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	return err;
}

static int hookfs_readdir(struct file *file, void *dirent,
	filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = hookfs_lower_file(file);
	err = vfs_readdir(lower_file, filldir, dirent);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	return err;
}

static long hookfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = hookfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file->f_path.dentry->d_inode,
				      lower_file->f_path.dentry->d_inode);
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long hookfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = hookfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int hookfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = hookfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "hookfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!HOOKFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "hookfs: lower mmap failed %d\n",
			    err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &hookfs_vm_ops;

	file->f_mapping->a_ops = &hookfs_aops; /* set our aops */
	if (!HOOKFS_F(file)->lower_vm_ops) /* save for our ->fault */
		HOOKFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int hookfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct hookfs_file_info), GFP_KERNEL);
	if (!HOOKFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link hookfs's file struct to lower's */
	hookfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = hookfs_lower_file(file);
		if (lower_file) {
			hookfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		hookfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(HOOKFS_F(file));
	else
		fsstack_copy_attr_all(inode, hookfs_lower_inode(inode));
out_err:
	return err;
}

static int hookfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = hookfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	return err;
}

/* release all lower object references & free the file info structure */
static int hookfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = hookfs_lower_file(file);
	if (lower_file) {
		hookfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(HOOKFS_F(file));
	return 0;
}

static int hookfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = hookfs_lower_file(file);
	hookfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	hookfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int hookfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = hookfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations hookfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= hookfs_read,
	.write		= hookfs_write,
	.unlocked_ioctl	= hookfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= hookfs_compat_ioctl,
#endif
	.mmap		= hookfs_mmap,
	.open		= hookfs_open,
	.flush		= hookfs_flush,
	.release	= hookfs_file_release,
	.fsync		= hookfs_fsync,
	.fasync		= hookfs_fasync,
};

/* trimmed directory options */
const struct file_operations hookfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= hookfs_readdir,
	.unlocked_ioctl	= hookfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= hookfs_compat_ioctl,
#endif
	.open		= hookfs_open,
	.release	= hookfs_file_release,
	.flush		= hookfs_flush,
	.fsync		= hookfs_fsync,
	.fasync		= hookfs_fasync,
};

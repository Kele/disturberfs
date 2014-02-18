/*
 * Copyright (c) 2013-2014      Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/fsdadm.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hookfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>


struct fsdadm_hook_int {
	uint64_t hi_id;
	struct super_block *hi_sb;
	int hi_type;
	union fsdadm_params hi_params;
	struct hookfs_hook hi_hook;
	struct list_head hi_node;
};

struct fsdadm_cb_int {
	uint64_t cbi_id;
	struct super_block *cbi_sb;
	void (*cbi_put)(struct super_block *);
};

static dev_t dev;
static int is_opened;
static struct cdev *cdev;
static LIST_HEAD(hooks);
static LIST_HEAD(callbacks);
static struct mutex lock;

static void fsdadm_readless_pre_read(void *data, struct file **file, char **buf,
    size_t *count, loff_t **pos)
{
	__attribute__((unused)) struct fsdadm_hook_int *hi = data;
	/* TODO: count -= delta? just like that? */
}

/*
 * Before calling this function, 'hi' should already be deleted from 'hooks'.
 */
static void fsdadm_release_hook(void *data, __attribute__((unused)) uint64_t id)
{
	struct fsdadm_hook_int *hi = data;
	kfree(hi);
}

static void fsdadm_put_super_callback(struct super_block *sb)
{
	struct fsdadm_hook_int *hi;
	struct list_head *node, *tmp;

	mutex_lock(&lock);
	list_for_each_safe(node, tmp, &hooks) {
		hi = list_entry(node, struct fsdadm_hook_int, hi_node);
		if (hi->hi_sb == sb) {
			list_del(&hi->hi_node);
			kfree(hi);
		}
	}
	mutex_unlock(&lock);
}

static int fsdadm_is_valid_readless(union fsdadm_params *par)
{
	if (par->readless.probability < 0 ||
	    par->readless.probability > 100)
		return 0;

	if (par->readless.range[0] > par->readless.range[1])
		return 0;

	return 1;
}

static int fsdadm_install_hook(struct fsdadm_ioc_hook *io)
{
	int err;
	struct file *file;
	struct fsdadm_hook_int *hi;
	struct super_block *sb;
	int type, op;


	hi = kzalloc(sizeof(*hi), GFP_KERNEL);
	if (hi == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&hi->hi_node);
	hi->hi_type = io->io_type;
	memcpy(&hi->hi_params, &io->io_params, sizeof(hi->hi_params));

	switch (hi->hi_type) {
	case FSDADM_TYPE_READLESS:
		if (!fsdadm_is_valid_readless(&hi->hi_params))
			return -EINVAL;
		hi->hi_hook.data = hi;
		hi->hi_hook.release = fsdadm_release_hook;
		hi->hi_hook.fn.pre_read = fsdadm_readless_pre_read;
		type = HOOKFS_TYPE_PRE;
		op = HOOKFS_OP_READ;
		break;

	default:
		kfree(hi);
		return -ENOTTY;
	}

	file = fget(io->io_fd);
	if (file == NULL)
		return -EBADF;
	sb = file->f_vfsmnt->mnt_sb;
	/* fsdadm_put_super_callback() can't happen here because of fget() TODO: are we sure? */
	err = hookfs_install_hook(sb, &hi->hi_hook, type, op, &hi->hi_id);
	if (err) {
		fput(file);
		return err;
	}

	mutex_lock(&lock);
	list_add(&hi->hi_node, &hooks);
	mutex_unlock(&lock);

	fput(file);

	return 0;
}

static int fsdadm_remove_hook(uint64_t id)
{
	struct fsdadm_hook_int *hi;
	int err;

	mutex_lock(&lock);
	list_for_each_entry(hi, &hooks, hi_node) {
		if (hi->hi_id == id)
			break;
	}
	if (hi != NULL) {
		list_del(&hi->hi_node);
		err =  hookfs_remove_hook(hi->hi_id, hi->hi_sb);
	} else {
		err = -EINVAL;
	}
	mutex_unlock(&lock);

	return err;
}

static int fsdadm_removeall(void)
{
	/* TODO: remove all hooks */
	return 0;
}

/*
 * fsdadm_open() returns:
 * 	0 	success
 * 	-EUSERS	the device is already is_opened by someone
 *	-EACCES	device is is_opened in different mode than O_RDWR
 */
static int fsdadm_open(struct inode *inode, struct file *filp)
{
	if ((filp->f_flags & O_ACCMODE) != O_RDWR)
		return -EACCES;

	mutex_lock(&lock);
	if (is_opened == 1) {
		mutex_unlock(&lock);
		return -EUSERS;
	}
	is_opened = 1;
	mutex_unlock(&lock);

	return 0;
}

static int fsdadm_release(struct inode *inode, struct file *filp)
{
	mutex_lock(&lock);
	is_opened = 0;
	mutex_lock(&lock);

	return 0;
}

static long fsdadm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case FSDADM_IOC_INSTALL: {
		struct fsdadm_ioc_hook io;

		if (copy_from_user(&io, (struct fsdadm_ioc_hook *)arg, sizeof(io))
		    < sizeof(io))
			return -EFAULT;

		err = fsdadm_install_hook(&io);
		if (err)
			return err;

		if (copy_to_user((struct fsdadm_ioc_hook *)arg, &io, sizeof(io))
		    < sizeof(io))
			return -EFAULT;

		return 0;
	}

	case FSDADM_IOC_REMOVE: {
		uint64_t id;
		if (get_user(id, (uint64_t *)arg))
			return -EFAULT;

		return fsdadm_remove_hook(id);
	}

	case FSDADM_IOC_REMOVEALL:
		return fsdadm_removeall();

	case FSDADM_IOC_LIST:
		/* TODO: that's the most complicated one */
		break;

	default:
		return -ENOTTY;
	}

	return 0;
}

static struct file_operations fsdadm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = fsdadm_ioctl,
	.compat_ioctl = fsdadm_ioctl,
	.open = fsdadm_open,
	.release = fsdadm_release
};

static int fsdadm_init(void)
{
	int err = 0;

	err = alloc_chrdev_region(&dev, 0, 1, "fsdadm");
	if (err)
		return err;

	mutex_init(&lock);

	cdev = cdev_alloc();
	if (cdev == NULL) {
		err = -ENOMEM;
		goto err_out;
	}
	cdev->ops = &fsdadm_fops;
	cdev->owner = THIS_MODULE;
	err = cdev_add(cdev, dev, 1);
	if (err)
		goto err_out;

	return 0;

err_out:
	if (cdev != NULL)
		kfree(cdev);
	mutex_destroy(&lock);
	unregister_chrdev_region(dev, 1);
	return err;
}

static void fsdadm_exit(void)
{
	fsdadm_removeall();
	cdev_del(cdev);	
	cdev = NULL;
	mutex_destroy(&lock);
	unregister_chrdev_region(dev, 1);
}

module_init(fsdadm_init);
module_exit(fsdadm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damian Bogel");
MODULE_DESCRIPTION("fsdadm");


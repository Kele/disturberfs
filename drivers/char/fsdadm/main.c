/*
 * Copyright (c) 2013-2014      Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsdadm.h>
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
	struct list_head cbi_node;
};

static dev_t dev;
static int is_opened;
static struct cdev *cdev;
static LIST_HEAD(hooks);
static LIST_HEAD(callbacks);
static struct mutex lock;
static struct class *class;
static struct device *device;

static void fsdadm_readless_pre_read(void *data, struct file **file, char **buf,
    size_t *count, loff_t **pos)
{
	struct fsdadm_hook_int *hi = data;
	printk(KERN_NOTICE "fsdadm: calling readless hook of id = %u\n", (unsigned)hi->hi_id);
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
	struct fsdadm_cb_int *cbi;
	struct list_head *node, *tmp;

	mutex_lock(&lock);
	list_for_each_safe(node, tmp, &hooks) {
		hi = list_entry(node, struct fsdadm_hook_int, hi_node);
		if (hi->hi_sb == sb) {
            printk(KERN_NOTICE "fsdadm: destroying hook %u\n", (unsigned)hi->hi_id);
			list_del(&hi->hi_node);
			kfree(hi);
		}
	}
	list_for_each_safe(node, tmp, &callbacks) {
		cbi = list_entry(node, struct fsdadm_cb_int, cbi_node);
		if (cbi->cbi_sb == sb) {
            printk(KERN_NOTICE "fsdadm: auto-destroying put_super_callback of id = %u\n",
                (unsigned)cbi->cbi_id);
			list_del(&cbi->cbi_node);
			kfree(cbi);
            break;
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

/* 'lock' has to be held */
static int _fsdadm_install_callback(struct super_block *sb)
{
	struct fsdadm_cb_int *cbi;
	int found = 0;
	int err;

	list_for_each_entry(cbi, &callbacks, cbi_node) {
		if (cbi->cbi_sb == sb) {
			found = 1;
			break;
		}
	}

	if (found)
		return 0;

	cbi = kzalloc(sizeof(*cbi), GFP_KERNEL);
	if (cbi == NULL)
		return -ENOMEM;

	cbi->cbi_sb = sb;
	err = hookfs_install_cb(sb, fsdadm_put_super_callback, &cbi->cbi_id);
	if (err) {
		kfree(cbi);
		return err;
	}

	list_add(&cbi->cbi_node, &callbacks);
	return 0;
}

/* 'lock' has to be held */
static int _fsdadm_remove_callback(struct super_block *sb)
{
	struct fsdadm_cb_int *cbi;
	list_for_each_entry(cbi, &callbacks, cbi_node) {
		if (cbi->cbi_sb == sb) {
			return hookfs_remove_cb(cbi->cbi_id, cbi->cbi_sb);
		}
	}
	return 0;
}

static int fsdadm_install_hook(struct fsdadm_ioc_hook *io)
{
	int err;
	struct file *file;
	struct fsdadm_hook_int *hi;
	struct super_block *sb;
	int type, op;

	file = fget(io->io_fd);
	if (file == NULL)
		return -EBADF;
	sb = file->f_vfsmnt->mnt_sb;

	hi = kzalloc(sizeof(*hi), GFP_KERNEL);
	if (hi == NULL) {
		err = -ENOMEM;
		goto alloc_failed;
	}

	INIT_LIST_HEAD(&hi->hi_node);
	hi->hi_type = io->io_type;
	hi->hi_sb = sb;
	memcpy(&hi->hi_params, &io->io_params, sizeof(hi->hi_params));

	switch (hi->hi_type) {
	case FSDADM_TYPE_READLESS:
		if (!fsdadm_is_valid_readless(&hi->hi_params)) {
			err = -EINVAL;
			goto invalid_params;
		}
		hi->hi_hook.data = hi;
		hi->hi_hook.release = fsdadm_release_hook;
		hi->hi_hook.fn.pre_read = fsdadm_readless_pre_read;
		type = HOOKFS_TYPE_PRE;
		op = HOOKFS_OP_READ;
		break;

	default:
		kfree(hi);
		fput(file);
		return -ENOTTY;
	}


	mutex_lock(&lock);
	err = _fsdadm_install_callback(sb);
	if (err)
		goto callback_failed;

	err = hookfs_install_hook(sb, &hi->hi_hook, type, op, &hi->hi_id);
	if (err)
		goto hook_failed;
	io->io_id = hi->hi_id;

	list_add(&hi->hi_node, &hooks);
	mutex_unlock(&lock);

	fput(file);

	return 0;


invalid_params:
	kfree(hi);
	goto alloc_failed;

hook_failed:
	_fsdadm_remove_callback(sb);

callback_failed:
	kfree(hi);
	mutex_unlock(&lock);

alloc_failed:
	fput(file);
	
	return err;
}

static int fsdadm_remove_hook(uint64_t id)
{
	struct fsdadm_hook_int *hi;
	int err;
	int found = 0;

	mutex_lock(&lock);
	list_for_each_entry(hi, &hooks, hi_node) {
		if (hi->hi_id == id) {
			found = 1;
			break;
		}
	}
	if (found) {
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
	struct fsdadm_hook_int *hi;
	struct fsdadm_cb_int *cbi;
	mutex_lock(&lock);
	while (!list_empty(&hooks)) {
		hi = list_first_entry(&hooks, struct fsdadm_hook_int, hi_node);
		list_del(&hi->hi_node);
		hookfs_remove_hook(hi->hi_id, hi->hi_sb);
	}
	while (!list_empty(&callbacks)) {
		cbi = list_first_entry(&callbacks, struct fsdadm_cb_int, cbi_node);
		list_del(&cbi->cbi_node);
		hookfs_remove_cb(cbi->cbi_id, cbi->cbi_sb);
	}
	mutex_unlock(&lock);
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
	mutex_unlock(&lock);

	return 0;
}

static long fsdadm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case FSDADM_IOC_INSTALL: {
		struct fsdadm_ioc_hook io;

		if (copy_from_user(&io, (struct fsdadm_ioc_hook *)arg, sizeof(io)))
			return -EFAULT;

		err = fsdadm_install_hook(&io);
		if (err)
			return err;

		if (copy_to_user((struct fsdadm_ioc_hook *)arg, &io, sizeof(io)))
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

	/* TODO: error checking */
	class = class_create(THIS_MODULE, "hookfsadm");
	if (IS_ERR(class)) {
		err = PTR_ERR(class);
		/* TODO: cleanup */
		return err;
	}

	device =  device_create(class, NULL, dev, NULL, "fsdadm");
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		/* TODO: cleanup */
		return err;
	}

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
    /* TODO: set to NULL */
	if (cdev != NULL)
		kfree(cdev);
	mutex_destroy(&lock);
	unregister_chrdev_region(dev, 1);
	return err;
}

static void fsdadm_exit(void)
{
    device_destroy(class, dev);
    class_destroy(class);
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


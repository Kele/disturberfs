/*
 * Copyright (c) 2013-2014 Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/export.h>
#include <linux/hookfs.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/types.h>

#include "hookfs_priv.h"

/*
 * sbi->write_lock has to be held
 */
uint64_t hookfs_new_id(struct super_block *sb)
{
	struct hookfs_sb_info *sbi = HOOKFS_SB(sb);
	WARN_ON(sbi->last_id + 1 < sbi->last_id);
	sbi->last_id++;
	return sbi->last_id;
}

int hookfs_install_hook(struct super_block *sb, struct hookfs_hook *hook, int type,
    int op, uint64_t *id)
{	
	int err = 0;
	int mode;
	struct hookfs_sb_info *sbi = HOOKFS_SB(sb);
	struct hookfs_hook_int *new_hook;

	new_hook = kzalloc(sizeof(*new_hook), GFP_KERNEL);
	if (new_hook == NULL)
		return -ENOMEM;

	new_hook->hi_data = hook->data;
	new_hook->hi_release = hook->release;
	INIT_LIST_HEAD(&new_hook->hi_node);
	kref_init(&new_hook->hi_ref);
	
	mutex_lock(&sbi->write_lock);

	*id = new_hook->hi_id = hookfs_new_id(sb);

	mode = HOOKFS_MKMODE(op, type);
	
	switch (mode) {
	case HOOKFS_MKMODE(HOOKFS_OP_READ, HOOKFS_TYPE_PRE):
		new_hook->hi_fn.pre_read = hook->fn.pre_read;
		break;
	case HOOKFS_MKMODE(HOOKFS_OP_READ, HOOKFS_TYPE_POST):
		new_hook->hi_fn.post_read = hook->fn.post_read;
		break;
	default:
		err = -EINVAL;
		break;
	}
	if (!err)
		list_add_rcu(&new_hook->hi_node, &sbi->hooks[mode]);
	else
		kfree(new_hook);
	mutex_unlock(&sbi->write_lock);
	
	return err;
}
EXPORT_SYMBOL(hookfs_install_hook);

void hookfs_release_hook(struct kref *kref)
{
	struct hookfs_hook_int *hook = container_of(kref, struct hookfs_hook_int, hi_ref);
	(*hook->hi_release)(hook->hi_data, hook->hi_id);
	kfree(hook);
}

int hookfs_remove_hook(uint64_t id, struct super_block *sb)
{
	struct hookfs_hook_int *hi;
	struct hookfs_sb_info *sbi = HOOKFS_SB(sb);
	int found = 0;

	mutex_lock(&sbi->write_lock);
	for (int i = 0; i < ARRAY_SIZE(sbi->hooks) && !found; i++) {
		list_for_each_entry_rcu(hi, &sbi->hooks[i], hi_node) {
			if (hi->hi_id == id) {
				found = 1;
				list_del_rcu(&hi->hi_node);
				synchronize_rcu();
				kref_put(&hi->hi_ref, hookfs_release_hook);
				break;
			}
		}
	}
	mutex_unlock(&sbi->write_lock);

	return found ? 0 : -EINVAL;
}
EXPORT_SYMBOL(hookfs_remove_hook);

int hookfs_install_cb(struct super_block *sb, void (*put)(struct super_block *), uint64_t *id)
{
	struct hookfs_sb_info *sbi = HOOKFS_SB(sb);
	struct hookfs_put_super_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (cb == NULL)
		return -ENOMEM;

	cb->cb_put = put;

	mutex_lock(&sbi->write_lock);
	*id = cb->cb_id = hookfs_new_id(sb);
	list_add(&cb->cb_node, &sbi->put_super_callbacks);
	mutex_unlock(&sbi->write_lock);

	return 0;
}
EXPORT_SYMBOL(hookfs_install_cb);

int hookfs_remove_cb(uint64_t id, struct super_block *sb)
{
	struct hookfs_put_super_cb *cb;
	struct hookfs_sb_info *sbi = HOOKFS_SB(sb);
	int found = 0;

	mutex_lock(&sbi->write_lock);
	list_for_each_entry(cb, &sbi->put_super_callbacks, cb_node) {
		if (cb->cb_id == id) {
			found = 1;
			list_del(&cb->cb_node);
			kfree(cb);
			break;
		}
	}
	mutex_unlock(&sbi->write_lock);

	return found ? 0 : -EINVAL;
}
EXPORT_SYMBOL(hookfs_remove_cb);

/*
 * Copyright (c) 2013-2014 Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _HOOKFS_H_
#define _HOOKFS_H_

#include <linux/types.h>

#define	HOOKFS_TYPE_POST	0
#define	HOOKFS_TYPE_PRE		1
#define HOOKFS_OP_READ		0
#define HOOKFS_OP_WRITE		2
#define HOOKFS_HOOK_MODES	4

#define HOOKFS_MKMODE(op, type) (op | type)

struct file;
struct super_block;

struct hookfs_hook {
	void *data;
	void (*release)(void *, uint64_t);
	union {
		void (*pre_read)(void *, struct file **, char **, size_t *, loff_t **);
		ssize_t (*post_read)(ssize_t, void *, struct file *, char *, size_t, loff_t *);
	} __rcu fn;
};

extern int hookfs_install_hook(struct super_block *sb, struct hookfs_hook *hook,
    int type, int op, uint64_t *id);
extern int hookfs_remove_hook(uint64_t id, struct super_block *sb);

extern int hookfs_install_cb(struct super_block *sb, void (*put)(struct super_block *),
    uint64_t *id);
extern int hookfs_remove_cb(uint64_t id, struct super_block *sb);

#endif	/* _HOOKFS_H_ */

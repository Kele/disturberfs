/*
 * Copyright (c) 2013-2014      Damian Bogel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _FSDADM_H_
#define _FSDADM_H_

#include <linux/types.h>

#ifndef __KERNEL__
#include <stdint.h>
#endif

#define FSDADM_IOC		('f' << 24 | 's' << 16 | 'd' << 8)
#define FSDADM_IOC_INSTALL	(FSDADM_IOC | 1)
#define FSDADM_IOC_REMOVE	(FSDADM_IOC | 2)
#define FSDADM_IOC_LIST		(FSDADM_IOC | 3)
#define FSDADM_IOC_REMOVEALL	(FSDADM_IOC | 4)

#define	FSDADM_TYPE_READLESS	1

union fsdadm_params {
	struct {
		uint8_t probability;
		uint32_t range[2];
	} readless;
} __attribute__((packed));

struct fsdadm_ioc_hook {
	uint64_t io_id;
	uint64_t io_fd;
	int32_t io_type;
	union fsdadm_params io_params;
} __attribute__((packed));

struct fsdadm_ioc_list {
	uint32_t io_count;
	struct fsdadm_hook *io_hooks;	
} __attribute__((packed));


#endif	/* _FSDADM_H_ */

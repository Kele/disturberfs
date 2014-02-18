HOOKFS_VERSION="0.1"

EXTRA_CFLAGS += -DHOOKFS_VERSION=\"$(HOOKFS_VERSION)\" --std=gnu99

obj-$(CONFIG_HOOK_FS) += hookfs.o

hookfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o hooks.o

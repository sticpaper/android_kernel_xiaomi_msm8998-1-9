#ifndef __KSU_H_FS
#define __KSU_H_FS

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define KERNEL_READ_WRITE_NEW_PROTOTYPES
#endif

#ifdef KERNEL_READ_WRITE_NEW_PROTOTYPES
ssize_t kernel_read_compat(struct file *, void *, size_t, loff_t *);
#else
ssize_t kernel_read_compat(struct file *, void *, unsigned long, loff_t *);
#endif

ssize_t kernel_write_compat(struct file *, const void *, size_t, loff_t *);
#endif

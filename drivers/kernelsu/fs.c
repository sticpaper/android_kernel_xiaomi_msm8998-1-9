#include "fs.h"

#ifdef KERNEL_READ_WRITE_NEW_PROTOTYPES
ssize_t kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos) {
	return kernel_read(p, buf, count, pos);
#else
ssize_t kernel_read_compat(struct file *p, void *buf, unsigned long count, loff_t *pos) {
	loff_t offset = pos ? *pos : 0;
	int result = kernel_read(p, *pos, (char *) buf, count);
	if (pos && result > 0)
		*pos = offset + result;
	return result;
#endif
}

ssize_t kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos) {
#ifdef KERNEL_READ_WRITE_NEW_PROTOTYPES
	return kernel_write(p, buf, count, pos);
#else
	loff_t offset = pos ? *pos : 0;
	ssize_t result = kernel_write(p, buf, count, offset);
	if (pos && result > 0)
		*pos = offset + result;
	return result;
#endif
}

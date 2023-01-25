#include <linux/err.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/security.h>
#ifndef OLD_SEC_HOOKS
#include <linux/lsm_hooks.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include "klog.h"
#include "ksu.h"

#ifdef CONFIG_KSU_BACKPORT
/* 在 Linux 3.18 中使用旧的挂钩 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#define OLD_SEC_HOOKS
#endif /* Linux version >= 3.18.0 < 4.4.0 */
#endif /* CONFIG_KSU_BACKPORT */

static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
	return -ENOSYS;
}

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return ksu_handle_rename(old_dentry, new_dentry);
}

#ifdef OLD_SEC_HOOKS
static struct security_operations ksu_hooks_ops = {
	.name =	"ksu_hooks",
	.task_prctl =	ksu_task_prctl,
	.inode_rename = ksu_inode_rename,
};
#else
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
};
#endif

void __init ksu_lsm_hook_init(void)
{
#ifdef OLD_SEC_HOOKS
	register_security(&ksu_hooks_ops);
#else /* OLD_SEC_HOOKS */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
#endif /* OLD_SEC_HOOKS */

	pr_info("security_add_hooks\n");
}
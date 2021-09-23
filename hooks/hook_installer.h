#ifndef HOOK_INST_H
#define HOOK_INST_H
#pragma GCC optimize("-fno-optimize-sibling-calls")

#include <linux/ftrace.h>
#include <linux/uaccess.h>

struct ftrace_hook {
    
    const char* name;
    void* function; // hook_addr
    void* original;

    unsigned long address;
    struct ftrace_ops ops;

};

#define CRT_HOOK(_name, _hook, _original) \
{ \
    .name = SYSCALL_NAME_CONVENTION(_name), \
    .function = (_hook), \
    .original = (_original), \
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1

#include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define NEW_CALL_CONVENTION 1
#endif

#if NEW_CALL_CONVENTION
#define SYSCALL_NAME_CONVENTION(name) ("__x64_" name)
#else
#define SYSCALL_NAME_CONVENTION(name) (name)
#endif

static int ftrace_resolve_addresses(struct ftrace_hook *hook)
{

#ifdef KPROBE_LOOKUP
    kallsyms_lookup_name_t kallsyms_lookup_name;

    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif

    hook->address = kallsyms_lookup_name(hook->name);
    if(!hook->address)
    {
        printk(KERN_ALERT "[chain] failed to resolve <%s>\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *) hook->original) = hook->address;
    return 0;
}

static void notrace ftrace_hook_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
}

int ftrace_install_hook(struct ftrace_hook *hook)
{
    int ret;

    // setting up ftrace_hook struct    
    if((ret = ftrace_resolve_addresses(hook)) > 0)
        return ret;

    hook->ops.func = ftrace_hook_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
    
    // ftrace_ops, hook_address, noremove, noreset
    if((ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0)) > 0)
        return ret;
    
    if((ret = register_ftrace_function(&hook->ops)) > 0)
        return ret;
    return 0;
}

int ftrace_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++)
    {
        err = ftrace_install_hook(&hooks[i]);
        if(err)
           return err;
    }
    return 0;
}
#endif

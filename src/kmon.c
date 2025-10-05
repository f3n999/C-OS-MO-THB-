#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules");
MODULE_DESCRIPTION("A simple LKM to monitor file access using kprobes.");
MODULE_VERSION("0.1");

// The target file to monitor
static char *target_file = "/etc/shadow";

// Define a kprobe to be placed at the entry of the do_sys_openat2 function
static struct kprobe kp = {
    .symbol_name = "do_sys_openat2",
};

// This function will be called when the kprobed function is entered
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // The filename is the second argument to the do_sys_openat2 syscall
    // On x86_64, the second argument is in the rsi register
    const char __user *filename_user = (const char __user *)regs->si;
    char filename[256];

    // Safely copy the filename from user space to kernel space
    if (strncpy_from_user(filename, filename_user, sizeof(filename)) > 0) {
        // Check if the accessed file is the one we are monitoring
        if (strcmp(filename, target_file) == 0) {
            pr_info("kmon: Detected access to %s by process %s (PID: %d)\n",
                    target_file, current->comm, current->pid);
        }
    }
    return 0;
}

static int __init kmon_init(void)
{
    int ret;
    pr_info("kmon: Initializing kernel module.\n");

    // Set the pre-handler for the kprobe
    kp.pre_handler = handler_pre;

    // Register the kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kmon: register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("kmon: Planted kprobe at %p\n", kp.addr);

    return 0;
}

static void __exit kmon_exit(void)
{
    // Unregister the kprobe
    unregister_kprobe(&kp);
    pr_info("kmon: Unloaded kernel module.\n");
}

module_init(kmon_init);
module_exit(kmon_exit);
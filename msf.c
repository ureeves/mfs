#include <linux/module.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/mm.h>

MODULE_AUTHOR("Eduardo Leegwater Simões <eduardols@protonmail.com>");
MODULE_DESCRIPTION("Foldable snapshots of virtual memory space");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

#define MSF_MAGIC 'm'

#define MSF_SNAP_CMD _IOW(MSF_MAGIC, 1, unsigned long)
#define MSF_APPLY_CMD _IOW(MSF_MAGIC, 2, unsigned long)
#define MSF_FORGET_CMD _IOW(MSF_MAGIC, 3, unsigned long)

// A `snap` command can be performed on a virtual address mapping to save dirty
// pages and marking them as clean.
//
// The pages are placed in a stack, and can either be folded back into the
// mapping using `msf_forget`, or popped from the stack using `msf_apply`.
static long msf_snap(unsigned long addr) {
    // TODO
    return 0;
}

// An `apply` command can be performed on a virtual address mapping to keep
// dirty pages and discard a snapshot.
//
// Since snapshots are in a stack, an apply operation is effectively just
// popping the stack.
static long msf_apply(unsigned long addr) {
    // TODO
    return 0;
}

// A `forget` command can be performed on a virtual address mapping to clean up
// dirty pages and use the snapshot instead.
//
// The pages on the stack are a popped, and reinserted back into the memory
// area, while cleaning any existing dirty page.
static long msf_forget(unsigned long addr) {
    struct vm_area_struct *vma;
    struct task_struct *task;

    task = current;

    vma = find_vma(task->mm, addr);
    if (vma) {

    }

    // TODO
    return 0;
}

static long msf_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    unsigned long addr;

    int ret = copy_from_user(&addr, (unsigned long*)arg, sizeof(unsigned long));

    if (ret != 0) {
        return -EFAULT;
    }

    switch (cmd) {
        case MSF_SNAP_CMD:
            pr_info("Received snap from userspace: %p\n", addr);
            return msf_snap(addr);
        case MSF_APPLY_CMD:
            pr_info("Received apply from userspace: %p\n", addr);
            return msf_apply(addr);
        case MSF_FORGET_CMD:
            pr_info("Received forget from userspace: %p\n", addr);
            return msf_forget(addr);
        default:
            return -ENOTTY;
    }

}

static const char *device_name = "msf";
static const char *device_class = "msf_class";

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = msf_ioctl,
};

dev_t dev = 0;

static struct class *dev_class;
static struct cdev msf_cdev;

static int __init msf_ioctl_init(void) {
    if((alloc_chrdev_region(&dev, 0, 1, "msf_dev")) <0){
        pr_err("Cannot allocate major number\n");
        return -1;
    }

    cdev_init(&msf_cdev, &fops);

    if((cdev_add(&msf_cdev,dev,1)) < 0){
        pr_err("Cannot add the device to the system\n");
        goto r_class;
    }

    if(IS_ERR(dev_class = class_create(THIS_MODULE, device_class))){
        pr_err("Cannot create the device class\n");
        goto r_class;
    }

    if(IS_ERR(device_create(dev_class, NULL, dev, NULL, device_name))){
        pr_err("Cannot create the device\n");
        goto r_device;
    }

    pr_err("Loaded %s module\n", device_name);
    return 0;

    r_device:
        class_destroy(dev_class);
    r_class:
        unregister_chrdev_region(dev, 1);
        return -1;
}

static void __exit msf_ioctl_exit(void) {
    device_destroy(dev_class,dev);
    class_destroy(dev_class);
    cdev_del(&msf_cdev);
    unregister_chrdev_region(dev, 1);
    pr_info("Unloaded %s module\n", device_name);
}

module_init(msf_ioctl_init);
module_exit(msf_ioctl_exit);

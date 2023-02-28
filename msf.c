#include <linux/module.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/radix-tree.h>

MODULE_AUTHOR("Eduardo Leegwater Simões <eduardols@protonmail.com>");
MODULE_DESCRIPTION("Foldable snapshots of virtual memory space");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

#define MSF_MAGIC 'm'

#define MSF_SNAP_CMD _IOW(MSF_MAGIC, 1, unsigned long)
#define MSF_APPLY_CMD _IOW(MSF_MAGIC, 2, unsigned long)
#define MSF_FORGET_CMD _IOW(MSF_MAGIC, 3, unsigned long)

// This tree is responsible for mapping processes to their respective memory
// snapshots.
RADIX_TREE(process_snapshots, GFP_ATOMIC);

// The collection of snapshots for a process.
struct msf_process_snapshots {
    // The initial snapshot stack
    struct msf_snapshot_stack *first;
    // The final snapshot stack
    struct msf_snapshot_stack *last;
};

// Each snapshot is part of a doubly linked list, allowing for easy lookup of
// snapshots for a given virtual memory area.
struct msf_snapshot_stack {
    // The starting address of the memory area.
    unsigned long start;
    // The end address of the memory area.
    unsigned long end;

    // Next member of the linked list.
    struct msf_snapshot_stack *next;
    // Previous member of the linked list.
    struct msf_snapshot_stack *prev;

    // The top of the snapshots stack.
    struct msf_snapshot *top;
};

// The pages representing a single `snap` of a memory.
struct msf_snapshot {
    // One level deeper in the stack.
    struct msf_snapshot *next;

    // The first page in the linked list of pages.
    struct msf_page *page;
    // The number of pages of this snapshot.
    size_t page_num;
};

// A single snapped memory page.
struct msf_page {
    // The next page that was snapped.
    struct msf_page *next;
    // The page data.
    unsigned char data[PAGE_SIZE];
};

static struct msf_snapshot_stack *lookup_snapshot_stack(struct msf_process_snapshots *snapshots, unsigned long addr) {
    struct msf_snapshot_stack *first = snapshots->first;

    // There are no stacks at all.
    if (!first) {
        return NULL;
    }

    // Easily rule out addresses that are not in the range.
    if (first->start < addr || snapshots->last->end >= addr) {
        return NULL;
    }

    // Traverse the list and return the element if the address falls in the
    // memory area.
    struct msf_snapshot_stack *curr = first;
    do {
        if (curr->start >= addr && curr->end < addr) {
            return curr;
        }
        curr = curr->next;
    } while (curr != first);

    return NULL;
}

// Pops the snapshot stack
static struct msf_snapshot *pop_snapshot(struct msf_snapshot_stack *stack) {
    struct msf_snapshot *top = stack->top;

    if (!top) {
        return NULL;
    }
    stack->top = top->next;

    return top;
}

// Free all the memory used for a snapshot
static void free_snapshot(struct msf_snapshot *snapshot) {
    struct msf_page *curr = snapshot->page;
    while (curr) {
        struct msg_page *prev = curr;
        curr = curr->next;
        kfree(prev);
    }
    kfree(snapshot);
}

// A `snap` command can be performed on a virtual address mapping to save dirty
// pages and marking them as clean.
//
// The pages are placed in a stack, and can either be folded back into the
// mapping using `msf_forget`, or popped from the stack using `msf_apply`.
static long msf_snap(unsigned long addr) {
    pr_info("Received `snap` from userspace: %p\n", addr);

    // Get current task and process id
    struct task_struct *current_task = current;
    pid_t pid = task_pid_nr(current_task);

    // TODO
    return 0;
}

// An `apply` command can be performed on a virtual address mapping to keep
// dirty pages and discard a snapshot.
//
// Since snapshots are in a stack, an apply operation is effectively just
// popping the stack.
static long msf_apply(unsigned long addr) {
    pr_info("Received `apply` from userspace: %p\n", addr);

    // Get current task and process id
    struct task_struct *current_task = current;
    pid_t pid = task_pid_nr(current_task);

    // Find snapshots in the process map,
    struct msf_process_snapshots *snapshots = radix_tree_lookup(&process_snapshots, pid);
    if (!snapshots) {
        pr_err("Process %d asked to `apply` %p but it has no snapshots", pid, addr);
        return EINVAL;
    }

    struct vm_area_struct *vma = find_vma(current_task->mm, addr);
    if (!vma) {
        pr_err("Process %d asked to `apply` %p but it has no such memory area", pid, addr);
        // TODO figure out if the snapshots should all be evicted in this case
        return EINVAL;
    }

    // Find a snapshot stack containing the given virtual address
    struct msf_snapshot_stack *snapshot_stack = lookup_snapshot_stack(snapshots, addr);
    if (!snapshot_stack) {
        pr_err("Process %d asked to `apply` %p but it has no snapshot stack for that memory area", pid, addr);
        return EINVAL;
    }

    // Pop a snapshot from the stack
    struct msf_snapshot *snapshot = pop_snapshot(snapshot_stack);
    if (!snapshot) {
        pr_err("Process %d asked to `apply` %p but it has no snapshots");
        return EINVAL;
    }

    free_snapshot(snapshot);

    return 0;
}

// A `forget` command can be performed on a virtual address mapping to clean up
// dirty pages and use the snapshot instead.
//
// The pages on the stack are a popped, and reinserted back into the memory
// area, while cleaning any existing dirty page.
static long msf_forget(unsigned long addr) {
    pr_info("Received `forget` from userspace: %p\n", addr);

    // Get current task and process id
    struct task_struct *current_task = current;
    pid_t pid = task_pid_nr(current_task);

    // Find snapshots in the process map,
    struct msf_process_snapshots *snapshots = radix_tree_lookup(&process_snapshots, pid);
    if (!snapshots) {
        pr_err("Process %d asked to `forget` %p but it has no snapshots", pid, addr);
        return EINVAL;
    }

    struct vm_area_struct *vma = find_vma(current_task->mm, addr);
    if (!vma) {
        pr_err("Process %d asked to `forget` %p but it has no such memory area", pid, addr);
        // TODO figure out if the snapshots should all be evicted in this case
        return EINVAL;
    }

    // Find a snapshot stack containing the given virtual address
    struct msf_snapshot_stack *snapshot_stack = lookup_snapshot_stack(snapshots, addr);
    if (!snapshot_stack) {
        pr_err("Process %d asked to `forget` %p but it has no snapshot stack for that memory area", pid, addr);
        return EINVAL;
    }

    // Pop a snapshot from the stack
    struct msf_snapshot *snapshot = pop_snapshot(snapshot_stack);
    if (!snapshot) {
        pr_err("Process %d asked to `forget` %p but it has no snapshots");
        return EINVAL;
    }

    // TODO forget the past dirty pages by replacing the process's pages with
    //  the popped pages. We also need to figure out what to do with the
    //  recently dirtied pages!

    return 0;
}

static long msf_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    unsigned long addr;

    int ret = copy_from_user(&addr, (unsigned long *) arg, sizeof(unsigned long));

    if (ret != 0) {
        return -EFAULT;
    }

    switch (cmd) {
        case MSF_SNAP_CMD:
            return msf_snap(addr);
        case MSF_APPLY_CMD:
            return msf_apply(addr);
        case MSF_FORGET_CMD:
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
    int ret;

    ret = alloc_chrdev_region(&dev, 0, 1, "msf_dev");
    if (ret < 0) {
        pr_err("Failed allocating a major number\n");
        return ret;
    }

    cdev_init(&msf_cdev, &fops);

    ret = cdev_add(&msf_cdev, dev, 1);
    if (IS_ERR(ret)) {
        pr_err("Failed adding device to the system\n");
        goto r_class;
    }

    ret = class_create(THIS_MODULE, device_class);
    if (IS_ERR(ret)) {
        pr_err("Failed creating the device class\n");
        goto r_class;
    }
    dev_class = ret;

    ret = device_create(dev_class, NULL, dev, NULL, device_name);
    if (IS_ERR(ret)) {
        pr_err("Cannot create the device\n");
        goto r_device;
    }

    pr_err("Loaded %s module\n", device_name);
    return 0;

    r_device:
        class_destroy(dev_class);
    r_class:
        unregister_chrdev_region(dev, 1);
        return ret;
}

static void __exit msf_ioctl_exit(void) {
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    cdev_del(&msf_cdev);
    unregister_chrdev_region(dev, 1);
    pr_info("Unloaded %s module\n", device_name);
}

module_init(msf_ioctl_init);
module_exit(msf_ioctl_exit);

#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <asm/csr.h>
#include <asm/uintr.h>

SYSCALL_DEFINE0(uintr_register_receiver)
{
    return -EINVAL;
}
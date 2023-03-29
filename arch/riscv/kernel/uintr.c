#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include <asm/csr.h>
#include <asm/uintr.h>
#include <asm/unistd.h>

#define pr_fmt(fmt) "%s: [%-25s]: " fmt, KBUILD_MODNAME, __func__

/* User Interrupt Sender Status Table Entry (UISTE) */
struct uist_entry {
	u8 valid;
	u8 reserved0;
	u16 send_vec;
	u16 reserved1;
	u16 uirs_index;
};

/* User Interrupt Receiver Status Table Entry (UIRSE) */
struct uirs_entry {
	u8 mode;
	u8 reserved0;
	u16 hartid;
	u32 reserved1;
	u64 irq;
};

struct uintr_receiver {
	struct uirs_entry *uirs;
	u16 uirs_index;
	/* trace active vector per bit */
	u64 uvec_mask;
};

/* User Interrupt Sender Status Table Context */
struct uist_ctx {
	struct uist_entry *uist;
	/* Protect UIST */
	spinlock_t uist_lock;
	refcount_t refs;
};

/* User Interrupt Sender */
struct uintr_sender {
	struct uist_ctx *uist_ctx;
	/* track active uist entries per bit */
	u64 uist_mask[BITS_TO_U64(UINTR_MAX_UIST_NR)];
};

static inline bool is_uintr_receiver(struct task_struct *t)
{
	return !!t->thread.ui_recv;
}

static inline bool is_uintr_sender(struct task_struct *t)
{
	return !!t->thread.ui_send;
}

static void free_uist(struct uist_ctx *uist_ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&uist_ctx->uist_lock, flags);
	kfree(uist_ctx->uist);
	uist_ctx->uist = NULL;
	spin_unlock_irqrestore(&uist_ctx->uist_lock, flags);

	kfree(uist_ctx);
}

static struct uist_ctx *alloc_uist(void)
{
	struct uist_ctx *uist_ctx;
	struct uist_entry *uist;

	uist_ctx = kzalloc(sizeof(*uist_ctx), GFP_KERNEL);
	if (!uist_ctx)
		return NULL;

	uist = kzalloc(sizeof(*uist) * UINTR_MAX_UIST_NR, GFP_KERNEL);
	if (!uist) {
		kfree(uist_ctx);
		return NULL;
	}

	uist_ctx->uist = uist;
	spin_lock_init(&uist_ctx->uist_lock);
	refcount_set(&uist_ctx->refs, 1);

	return uist_ctx;
}

static void put_uist_ref(struct uist_ctx *uist_ctx)
{
	if (refcount_dec_and_test(&uist_ctx->refs))
		free_uist(uist_ctx);
}

static struct uist_ctx *get_uist_ref(struct uist_ctx *uist_ctx)
{
	refcount_inc(&uist_ctx->refs);
	return uist_ctx;
}

static int init_sender(void)
{
	struct task_struct *t = current;
	struct uintr_sender *ui_send;

	ui_send = kzalloc(sizeof(*ui_send), GFP_KERNEL);
	if (!ui_send)
		return -ENOMEM;

	ui_send->uist_ctx = alloc_uist();
	if (!ui_send->uist_ctx) {
		pr_debug("Failed to allocate user-interrupt sender table\n");
		kfree(ui_send);
		return -ENOMEM;
	}

	return 0;
}

SYSCALL_DEFINE0(uintr_register_receiver)
{
	pr_info("Initializing uintr receiver...\n");
	return -EINVAL;
}

SYSCALL_DEFINE1(uintr_create_fd, u64, vector)
{
	pr_info("Creating fd from vector: 0x%lx\n.", vector);
	return -EINVAL;
}

SYSCALL_DEFINE1(uintr_register_sender, int, uintrfd)
{
	pr_info("Initializing uintr sender...\n");
	return -EINVAL;
}


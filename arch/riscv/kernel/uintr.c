#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>
#include <linux/task_work.h>

#include <asm/csr.h>
#include <asm/uintr.h>
#include <asm/unistd.h>

#define pr_fmt(fmt)                                                       \
	"[CPU %d] %s: [%-35s]: " fmt, smp_processor_id(), KBUILD_MODNAME, \
		__func__

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
	u16 uirs_index;
	u64 uvec_mask; /* trace active vector per bit */
	struct task_struct *task;
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
	struct task_struct *task;
};

/* User Interrupt File Descriptor Context */
struct uintrfd_ctx {
	struct uintr_receiver *recv;
	u8 uvec;
};

static int uintrfd_release(struct inode *inode, struct file *file)
{
	struct uintrfd_ctx *uintrfd_ctx = file->private_data;

	pr_info("release uintrfd for uvec=%d\n", uintrfd_ctx->uvec);

	clear_bit(uintrfd_ctx->uvec,
		  (unsigned long *)&uintrfd_ctx->recv->uvec_mask);
	kfree(uintrfd_ctx);

	return 0;
}

static const struct file_operations uintrfd_fops = { .release = uintrfd_release,
						     .llseek = noop_llseek };

static inline bool is_uintr_receiver(struct task_struct *t)
{
	return !!t->thread.ui_recv && t->thread.ui_recv->task == t;
}

static inline bool is_uintr_sender(struct task_struct *t)
{
	return !!t->thread.ui_send && t->thread.ui_send->task == t;
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

	/* TODO: misaligned table */
	if ((unsigned long)uist & 0xfff) {
		kfree(uist_ctx);
		kfree(uist);
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
		pr_info("Failed to allocate user-interrupt sender table\n");
		kfree(ui_send);
		return -ENOMEM;
	}

	ui_send->task = get_task_struct(t);

	t->thread.ui_send = ui_send;

	return 0;
}

static void load_uirs(unsigned int entry, struct uirs_entry *uirs)
{
	u64 low, high;

	uintc_read_low(entry, &low);
	uintc_read_high(entry, &high);

	uirs->mode = low;
	uirs->hartid = low >> 16;
	uirs->irq = high;

	/* reserved bits ignored */
	uirs->reserved0 = uirs->reserved1 = 0;
}

static void store_uirs(unsigned entry, struct uirs_entry *uirs)
{
	u64 low, high;

	low = uirs->mode | (uirs->hartid << 16);
	high = uirs->irq;

	uintc_write_low(entry, low);
	uintc_write_high(entry, high);
}

static void free_uist_entry(unsigned int entry)
{
	struct task_struct *t = current;
	unsigned long flags;

	if (entry >= UINTR_MAX_UIST_NR)
		return;

	if (!is_uintr_sender(t))
		return;

	spin_lock_irqsave(&t->thread.ui_send->uist_ctx->uist_lock, flags);
	memset(&t->thread.ui_send->uist_ctx->uist[entry], 0,
	       sizeof(struct uist_entry));
	spin_unlock_irqrestore(&t->thread.ui_send->uist_ctx->uist_lock, flags);

	clear_bit(entry, (unsigned long *)&t->thread.ui_send->uist_mask);
}

SYSCALL_DEFINE0(uintr_register_receiver)
{
	int ret;
	struct uintr_receiver *ui_recv;
	struct task_struct *t = current;

	if (is_uintr_receiver(t))
		return -EBUSY;

	ui_recv = kzalloc(sizeof(*ui_recv), GFP_KERNEL);
	if (!ui_recv)
		return -ENOMEM;

	ret = uintc_alloc();
	if (ret < 0) {
		pr_info("alloc uintc entry failed for task=%d\n", t->pid);

		kfree(ui_recv);
		return ret;
	}

	/* clear pending bits */
	uintc_write_low(ret, 0UL);
	uintc_read_high(ret, NULL);

	ui_recv->task = get_task_struct(t);
	ui_recv->uirs_index = ret;

	t->thread.ui_recv = ui_recv;

	pr_info("receiver=%d entry=%d\n", t->pid, ret);
	return 0;
}

SYSCALL_DEFINE1(uintr_create_fd, u64, vector)
{
	int ret, uintrfd;
	struct uintrfd_ctx *uintrfd_ctx;
	struct task_struct *t = current;
	struct uintr_receiver *ui_recv;

	if (!is_uintr_receiver(t))
		return -EINVAL;

	ui_recv = t->thread.ui_recv;

	if (ui_recv->uvec_mask & BIT_ULL(vector))
		return -EBUSY;

	uintrfd_ctx = kzalloc(sizeof(*uintrfd_ctx), GFP_KERNEL);
	if (!uintrfd_ctx)
		return -ENOMEM;

	uintrfd_ctx->uvec = vector;
	set_bit(vector, (unsigned long *)&ui_recv->uvec_mask);

	uintrfd_ctx->recv = ui_recv;

	uintrfd = anon_inode_getfd("[uintrfd]", &uintrfd_fops, uintrfd_ctx,
				   O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (uintrfd < 0) {
		ret = uintrfd;
		clear_bit(vector, (unsigned long *)&ui_recv->uvec_mask);
		kfree(uintrfd_ctx);
		return uintrfd;
	}

	pr_info("receiver=%d uvec=%llu uintrfd=%d\n", t->pid, vector, uintrfd);
	return uintrfd;
}

SYSCALL_DEFINE1(uintr_register_sender, int, uintrfd)
{
	// pr_info("Initializing uintr sender...\n");
	int ret = 0, entry;
	unsigned long flags;
	struct fd f;
	struct file *uintr_f;
	struct uintrfd_ctx *uintrfd_ctx;
	struct task_struct *t = current;
	struct uintr_sender *ui_send;
	struct uist_entry *uiste = NULL;

	f = fdget(uintrfd);
	uintr_f = f.file;
	if (!uintr_f)
		return -EBADF;

	if (uintr_f->f_op != &uintrfd_fops) {
		pr_err("Wrong uintrfd=%d\n", uintrfd);
		ret = -EOPNOTSUPP;
		goto out_fdput;
	}

	uintrfd_ctx = uintr_f->private_data;

	if (is_uintr_sender(t)) {
		entry = find_first_zero_bit(
			(unsigned long *)t->thread.ui_send->uist_mask,
			UINTR_MAX_UIST_NR);
		if (entry >= UINTR_MAX_UIST_NR) {
			ret = -ENOSPC;
			goto out_fdput;
		}
	} else {
		entry = 0;
		ret = init_sender();
		if (ret)
			goto out_fdput;
	}
	ui_send = t->thread.ui_send;

	ret = entry;
	set_bit(entry, (unsigned long *)ui_send->uist_mask);

	spin_lock_irqsave(&ui_send->uist_ctx->uist_lock, flags);
	uiste = &ui_send->uist_ctx->uist[entry];
	uiste->valid = 0x1;
	uiste->send_vec = uintrfd_ctx->uvec;
	uiste->uirs_index = uintrfd_ctx->recv->uirs_index;
	pr_info("sender=%d entry=%d va=%px\n", t->pid, entry, uiste);
	spin_unlock_irqrestore(&ui_send->uist_ctx->uist_lock, flags);

out_fdput:
	fdput(f);
	return ret;
}

void uintr_free(struct task_struct *t)
{
	int uirs_index;
	struct uintr_receiver *ui_recv;
	struct uintr_sender *ui_send;

	if (WARN_ON_ONCE(t != current))
		return;

	if (is_uintr_receiver(t)) {
		ui_recv = t->thread.ui_recv;
		uirs_index = ui_recv->uirs_index;
		uintc_dealloc(ui_recv->uirs_index);
		put_task_struct(ui_recv->task);
		kfree(ui_recv);
		t->thread.ui_recv = NULL;
		csr_write(CSR_SUIRS, 0UL);
		pr_info("freed receiver=%d entry=%d\n", t->pid, uirs_index);
	}

	if (is_uintr_sender(t)) {
		ui_send = t->thread.ui_send;
		put_uist_ref(ui_send->uist_ctx);
		put_task_struct(ui_send->task);
		kfree(ui_send);
		t->thread.ui_send = NULL;
		csr_write(CSR_SUIST, 0UL);
		pr_info("freed sender=%d\n", t->pid);
	}
}

asmlinkage void riscv_uintr_restore(struct pt_regs *regs)
{
	uintc_init();

	uintr_recv_restore(regs);

	uintr_send_restore();
}

void uintr_recv_restore(struct pt_regs *regs)
{
	struct task_struct *t = current;
	struct uintr_receiver *ui_recv;
	struct uirs_entry uirs;

	/* always delegate user interrupt to read/write uie and uip */
	csr_set(CSR_SIDELEG, IE_USIE);

	if (!is_uintr_receiver(t)) {
		csr_write(CSR_SUIRS, 0UL);
		csr_clear(CSR_UIE, IE_USIE);
		csr_clear(CSR_UIP, IE_USIE);
		return;
	}

	ui_recv = t->thread.ui_recv;

	load_uirs(ui_recv->uirs_index, &uirs);
	uirs.hartid = smp_processor_id();
	uirs.mode = 0x2;
	store_uirs(ui_recv->uirs_index, &uirs);
	csr_write(CSR_SUIRS, (1UL << 63) | ui_recv->uirs_index);

	csr_set(CSR_UIE, IE_USIE);
	if (uirs.irq)
		csr_set(CSR_UIP, IE_USIE);
	else
		csr_clear(CSR_UIP, IE_USIE);

	// if (uirs.irq)
	// 	pr_err("uirs restore: index=%d irq=%llu utvec=0x%lx uepc=0x%lx uscratch=0x%lx\n",
	// 	       (u32)ui_recv->uirs_index, uirs.irq, regs->utvec,
	// 	       regs->uepc, regs->uscratch);

	/* restore U-mode CSRs */
	csr_write(CSR_UEPC, regs->uepc);
	csr_write(CSR_UTVEC, regs->utvec);
	csr_write(CSR_USCRATCH, regs->uscratch);
}

void uintr_send_restore(void)
{
	struct task_struct *t = current;

	if (!is_uintr_sender(t)) {
		csr_write(CSR_SUIST, 0UL);
		return;
	}

	csr_write(CSR_SUIST,
		  (1UL << 63) | (1UL << 44) |
			  PFN_DOWN(virt_to_phys(
				  t->thread.ui_send->uist_ctx->uist)));
}

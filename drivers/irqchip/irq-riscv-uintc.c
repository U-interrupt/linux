#include "linux/bitmap.h"
#define pr_fmt(fmt) "riscv-uintc: " fmt

#include <linux/cpu.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <asm/smp.h>
#include <asm/uintr.h>

#define UINTC_WIDTH 32

struct uintc_priv {
	struct cpumask lmask;
	void __iomem *regs;
	resource_size_t start;
	resource_size_t size;
	u32 nr;
	void *mask;
	spinlock_t lock;
};

struct uintc_handler {
	bool present;
	struct uintc_priv *priv;
};

static DEFINE_PER_CPU(struct uintc_handler, uintc_handlers);

static int __init __uintc_init(struct device_node *node,
			       struct device_node *parent)
{
	int error = 0, nr_contexts, i;
	struct uintc_priv *priv;
	struct uintc_handler *handler;
	struct resource uintc_res;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	if (of_address_to_resource(node, 0, &uintc_res)) {
		error = -EIO;
		goto out_free;
	}

	priv->start = uintc_res.start;
	priv->size = resource_size(&uintc_res);
	priv->nr = priv->size / UINTC_WIDTH;
	priv->regs = ioremap(uintc_res.start, priv->size);
	if (WARN_ON(!priv->regs)) {
		error = -EIO;
		goto out_free;
	}

	priv->mask = bitmap_alloc(priv->nr, GFP_KERNEL);
	if (!priv->mask) {
		error = -ENOMEM;
		goto out_iounmap;
	}
	bitmap_clear(priv->mask, 0, priv->nr);
	bitmap_set(priv->mask, 1, 4);

	spin_lock_init(&priv->lock);

	error = -EINVAL;
	nr_contexts = of_irq_count(node);
	if (WARN_ON(!nr_contexts))
		goto out_iounmap;

	for (i = 0; i < nr_contexts; i++) {
		struct of_phandle_args parent;
		int cpu;
		unsigned long hartid;

		if (of_irq_parse_one(node, i, &parent)) {
			pr_err("failed to parse parent for context %d.\n", i);
			continue;
		}

		if (parent.args[0] != IRQ_U_SOFT) {
			continue;
		}

		error = riscv_of_parent_hartid(parent.np, &hartid);
		if (error < 0) {
			pr_warn("failed to parse hart ID for context %d.\n", i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("invalid cpuid for context %d.\n", i);
			continue;
		}

		handler = per_cpu_ptr(&uintc_handlers, cpu);
		if (handler->present) {
			pr_warn("handler already present for context %d.\n", i);
			continue;
		}

		cpumask_set_cpu(cpu, &priv->lmask);
		handler->present = true;
		handler->priv = priv;
	}

	pr_info("%pOFP: %d entries available\n", node, priv->nr);
	return 0;

out_iounmap:
	iounmap(priv->regs);
out_free:
	kfree(priv);
	return error;
}

IRQCHIP_DECLARE(riscv_uintc, "riscv,uintc0", __uintc_init);

int uintc_alloc(void)
{
	int nr;
	unsigned long flags;
	struct uintc_handler *handler;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -ENODEV;

	spin_lock_irqsave(&handler->priv->lock, flags);
	nr = find_first_zero_bit(handler->priv->mask, handler->priv->nr);
	if (nr >= handler->priv->nr)
		return -ENOSPC;
	set_bit(nr, handler->priv->mask);
	spin_unlock_irqrestore(&handler->priv->lock, flags);

	return nr;
}

int uintc_dealloc(int index)
{
	unsigned long flags;
	struct uintc_handler *handler;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	spin_lock_irqsave(&handler->priv->lock, flags);
	clear_bit(index, handler->priv->mask);
	spin_unlock_irqrestore(&handler->priv->lock, flags);
	return 0;
}

int uintc_send(int index)
{
	struct uintc_handler *handler;
	u64 __iomem *reg;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	reg = handler->priv->regs + index * UINTC_WIDTH;

	writeq(0x1, reg);
	return 0;
}

int uintc_read_low(int index, u64 *value)
{
	struct uintc_handler *handler;
	u64 __iomem *reg;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	reg = handler->priv->regs + index * UINTC_WIDTH + 0x8;

	if (value)
		*value = readq(reg);
	return 0;
}

int uintc_write_low(int index, u64 value)
{
	struct uintc_handler *handler;
	u64 __iomem *reg;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	reg = handler->priv->regs + index * UINTC_WIDTH + 0x8;

	writeq(value, reg);
	return 0;
}

int uintc_read_high(int index, u64 *value)
{
	struct uintc_handler *handler;
	u64 __iomem *reg;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	reg = handler->priv->regs + index * UINTC_WIDTH + 0x10;

	if (value)
		*value = readq(reg);
	return 0;
}

int uintc_write_high(int index, u64 value)
{
	struct uintc_handler *handler;
	u64 __iomem *reg;

	handler = this_cpu_ptr(&uintc_handlers);
	if (!handler->present)
		return -EINVAL;

	if (index >= handler->priv->nr)
		return -EINVAL;

	reg = handler->priv->regs + index * UINTC_WIDTH + 0x10;

	writeq(value, reg);
	return 0;
}
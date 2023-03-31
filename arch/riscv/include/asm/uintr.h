#ifndef _ASM_RISCV_UINTR_H
#define _ASM_RISCV_UINTR_H

#ifdef CONFIG_RISCV_UINTR

#include <linux/linkage.h>

#define UINTR_MAX_UIST_NR 512

struct pt_regs;
struct task_struct;

int uintc_init(void);

int uintc_alloc(void);
int uintc_dealloc(int index);

int uintc_send(int index);
int uintc_write_low(int index, u64 value);
int uintc_read_low(int index, u64 *value);
int uintc_write_high(int index, u64 value);
int uintc_read_high(int index, u64 *value);

void uintr_free(struct task_struct *t);

asmlinkage void riscv_uintr_restore(struct pt_regs *regs);

/*
 * Synchronize receiver status to UINTC and raise user interrupt if kernel returns to
 * a receiver with pending interrupt requests.
 * 
 * Each time a receiver traps into a U-mode trap handler, it can be migrated to another hart
 * caused by U-ecall or other exceptions thus we must save and restore CPU-local registers such
 * as `upec`, `utvec` and `uscratch`. 
 */
void uintr_recv_restore(struct pt_regs *regs);

/*
 * Initialize starting frame number of sender status table.
 */
void uintr_send_restore(void);

#else

static inline void uintr_free(struct task_struct *t) {}

#endif /* CONFIG_RISCV_UINTR */

#endif /* _ASM_RISCV_UINTR_H */
#ifndef _ASM_RISCV_UINTR_H
#define _ASM_RISCV_UINTR_H

#ifdef CONFIG_RISCV_UINTR

#define UINTR_MAX_UIST_NR 256

int uintc_alloc(void);
int uintc_dealloc(int index);

int uintc_send(int index);
int uintc_write_low(int index, u64 value);
int uintc_read_low(int index, u64 *value);
int uintc_write_high(int index, u64 value);
int uintc_read_high(int index, u64 *value);

#endif /* CONFIG_RISCV_UINTR */

#endif /* _ASM_RISCV_UINTR_H */
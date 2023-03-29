#ifndef _ASM_ENTRY_COMMON_H
#define _ASM_ENTRY_COMMON_H

#include <asm/uintr.h>

static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
{

}
#define arch_enter_from_user_mode arch_enter_from_user_mode

static __always_inline void arch_exit_to_user_mode()
{

}
#define arch_exit_to_user_mode arch_exit_to_user_mode

#endif
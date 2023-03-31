#ifndef _ASM_ENTRY_COMMON_H
#define _ASM_ENTRY_COMMON_H

#include <linux/sched.h>

#include <asm/uintr.h>

struct pt_regs;

static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
{
    
}
#define arch_enter_from_user_mode arch_enter_from_user_mode

static __always_inline void arch_exit_to_user_mode(void)
{

}
#define arch_exit_to_user_mode arch_exit_to_user_mode

#endif
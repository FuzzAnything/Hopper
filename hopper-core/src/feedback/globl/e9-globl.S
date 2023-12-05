.text
.globl __hopper_inc_stmt_index
.globl __hopper_reset_stmt_index
.globl __hopper_last_stmt_index
.globl __hopper_enable_cov
.globl __hopper_disable_cov
.globl __hopper_set_context
__hopper_inc_stmt_index:
        incw %ds:0x3B0108
        incl %ds:0x3B0008
        ret
__hopper_reset_stmt_index:
        movw $0, %ds:0x3B0108
        movl $0, %ds:0x3B0008
        ret
__hopper_last_stmt_index:
        movw $0xFFFF, %ds:0x3B0108
        ret
__hopper_enable_cov:
        movl $0, %ds:0x3B0100
        ret
__hopper_disable_cov:
        movl $0xFFFFFFFF, %ds:0x3B0100
        ret
__hopper_set_context:
        movq %rdi, %ds:0x3B0110
        ret
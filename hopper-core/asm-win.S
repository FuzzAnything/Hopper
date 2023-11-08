.text
.globl __hopper_inc_stmt_index
.globl __hopper_reset_stmt_index
.globl __hopper_last_stmt_index
.globl __hopper_enable_cov
.globl __hopper_disable_cov
.globl __hopper_set_context
__hopper_inc_stmt_index:
        incw 0x47ff1000
        incl %ds:0x47fb0008
        ret
__hopper_reset_stmt_index:
        movw $0,0x47ff1000
        movl $0, %ds:0x47fb0008
        ret
__hopper_last_stmt_index:
        movw $0xFFFF, 0x47ff1000
        ret
__hopper_enable_cov:
        movl $0, 0x47ff2000
        ret
__hopper_disable_cov:
        movl $0xFFFFFFFF, 0x47ff2000
        ret
__hopper_set_context:
        ret
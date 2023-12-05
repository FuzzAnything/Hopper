
#include "stdint.h"

extern __thread uint32_t __hopper_prev_loc; // = 0xFFFFFFFF;
extern __thread uint32_t __hopper_context; // = 0;
extern uint32_t* __hopper_stmt_index_ptr;

void __hopper_disable_cov() {
  __hopper_prev_loc = 0xFFFFFFFF;
}

void __hopper_enable_cov() {
  __hopper_prev_loc = 0x0;
}

void __hopper_set_context(uint32_t context) {
  __hopper_context = context;
}

void __hopper_inc_stmt_index() {
  uint32_t index = *__hopper_stmt_index_ptr;
  *__hopper_stmt_index_ptr = index + 1;
}

void __hopper_reset_stmt_index() {
  *__hopper_stmt_index_ptr = 0;
}

void __hopper_last_stmt_index() {
  *__hopper_stmt_index_ptr = 0xFFFF;
}

uint32_t __hopper_get_stmt_index() {
  return *__hopper_stmt_index_ptr;
}

void __hopper_branch_stub(uint32_t stub) {
  stub += 1;  // do sth
}

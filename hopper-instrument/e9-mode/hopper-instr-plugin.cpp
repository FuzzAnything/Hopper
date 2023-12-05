/*
 * Copyright (C) 2021 National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * NOTE: As a special exception, this file is under the MIT license.  The
 *       rest of the E9Patch/E9Tool source code is under the GPLv3 license.
 */

/*
 * This is an example E9Tool plugin.  It implements a limit on control-flow
 * transfer instructions such as calls, jumps, and returns.  When the limit
 * is reached, it will execute the int3 instruction generating a SIGTRAP.
 *
 * To compile:
 *          $ g++ -std=c++11 -fPIC -shared -o example.so -O2 \
 *              examples/plugins/example.cpp -I . -I capstone/include/
 *
 * To use:
 *          $ ./e9tool -M 'plugin(example).match()' \
 *                     -P 'plugin(example).patch()' program
 *          $ ./a.out
 *          Trace/breakpoint trap
 */

#include <sys/mman.h>

#include <sstream>
#include <string>
#include <algorithm>
#include <vector>

#include "config.h"
#include "e9plugin.h"
#include "stdarg.h"

using namespace e9tool;

enum CMP_TYPE {
  INSTCMP = 1,
  STRCMP = 17,
  STRNCMP = 18,
  MEMCMP = 19,
};

#define NUM_REG REGISTER_RIP
#define STACK_FRAME_SIZE 4096

static std::map<intptr_t, CMP_TYPE> CmpPlt;

static FILE *log = NULL;
static bool enable_cmp_one_byte = true;
// experimental feature for static data flow tracking
static bool enable_sdft = false;
static std::vector<int> blacklist_ids;
int num_cmp = 0;
int num_bad_cmp = 0;
int num_fn_cmp = 0;
int num_opt1_cmp = 0;
int num_opt2_cmp = 0;
int num_opt3_cmp = 0;
int num_patch_cmp = 0;
int reg_count[NUM_REG] = { 0 };
bool reg_taint[NUM_REG] = { 0 };
bool stack_taint[STACK_FRAME_SIZE] = { 0 };

static void print_message(bool fatal, const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  if (log == NULL) {
    log = fopen("/tmp/e9cmp.log", "a");
    if (log != NULL) setvbuf(log, NULL, _IONBF, 0);
  }
  if (log == NULL) {
    if (fatal) abort();
    return;
  }
  vfprintf(log, msg, ap);
  if (fatal) abort();
  va_end(ap);
}

#define warn(msg, ...) \
  print_message(false, "e9cmp warn: " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) \
  print_message(true, "e9cmp runtime error: " msg "\n", ##__VA_ARGS__)
#define log(msg, ...) \
  print_message(false, "e9cmp log: " msg "\n", ##__VA_ARGS__)

std::string fetch_offset(const int32_t offset_ptr, int entry_size, int32_t max_offset) {
  std::stringstream code;
  // mov %ds:offset_ptr, %eax
  code << 0x8b << ',' << 0x04 << ',' << 0x25 << ','
       << "{\"int32\":" << offset_ptr << "},";
  // and %eax, CMP_AREA_SIZE - 1
  code << 0x25 << ',' << "{\"int32\":" << max_offset << "},";
  // mov %eax %r10d
  code << 0x41 << ',' << 0x89 << ',' << 0xc2 << ',';
  // add %eax, $0x20
  code << 0x83 << ',' << 0xc0 << ',' << entry_size << ',';
  // mov %eax, %ds:offset_ptr
  code << 0x89 << ',' << 0x04 << ',' << 0x25 << ','
       << "{\"int32\":" << offset_ptr << "},";
  return code.str();
}

/*
 * Initialize the counters and the trampoline.
 */
extern void *e9_plugin_init(const Context *cxt) {
  // The e9_plugin_init() is called once per plugin by E9Tool.  This can
  // be used to emit additional E9Patch messages, such as address space
  // reservations and trampoline templates.
  const int32_t cmp_area_ptr = INSTR_AREA;
  const int32_t instr_info_ptr = INFO_AREA;
  const int32_t cmp_offset = instr_info_ptr;

  if (getenv("HOPPER_DISABLE_CMP_ONE_BYTE") != nullptr) {
    warning("disable cmp one byte!");
    enable_cmp_one_byte = false;
  }
  if (getenv("HOPPER_ENABLE_SDFT") != nullptr) {
    warning("enable static data flow tracking!");
    enable_sdft = true;
  }
  const char * blacklist = getenv("HOPPER_CMP_BLACKLIST");
  if (blacklist!= nullptr) {
    warning("cmp blacklist %s!", blacklist);
    char* str = (char*) blacklist;
    char *end = str;
    while(*end) {
      int n = strtol(str, &end, 10);
      // printf("%d\n", n);
      blacklist_ids.push_back(n);
      while (*end == ',') {
        end++;
      }
      str = end;
    }
  }

#ifndef WINDOWS
  sendReserveMessage(cxt->out, cmp_area_ptr, INSTR_ALL_SIZE, /*absolute=*/true);
  sendReserveMessage(cxt->out, CANARY_PTR, CANARY_AREA_SIZE, /*absolute=*/true);
#endif

  /*
   * Mext we need to define the trampoline template using a "trampoline"
   * E9Patch API message.
   */

  // The trampoline template is specified using a form of annotated
  // machine code.  For more information about the trampoline template
  // language, please see e9patch-programming-guide.md

  // Save state:
  //
  // lea -0x4000(%rsp),%rsp
  // push %r10
  // push %rax
  // seto %al
  // lahf
  // push %rax
  //
  std::stringstream prefix_code;
  prefix_code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ',' << 0x00
       << ',' << 0xc0 << ',' << 0xff << ',' << 0xff << ',';
  prefix_code << 0x41 << ',' << 0x52 << ',';
  prefix_code << 0x50 << ',';
  prefix_code << 0x0f << ',' << 0x90 << ',' << 0xc0 << ',';
  prefix_code << 0x9f << ',';
  prefix_code << 0x50 << ',';

  // Restore flags and eax first
  // pop %rax
  // add $0x7f,%al
  // sahf
  // pop %rax
  std::stringstream restore_code;
  restore_code << "\".Lok1\",";
  restore_code << 0x58 << ',';
  restore_code << 0x04 << ',' << 0x7f << ',';
  restore_code << 0x9e << ',';
  restore_code << 0x58 << ',';

  // Restore state & return from trampoline:
  //
  // pop %r10
  // lea 0x4000(%rsp),%rsp
  //
  std::stringstream restore_code2;
  restore_code2 << "\".Lok2\",";
  restore_code2 << 0x41 << ',' << 0x5a << ',';
  restore_code2 << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ',' << 0x00
       << ',' << 0x40 << ',' << 0x00 << ',' << 0x00;

  std::stringstream code;
  code << prefix_code.str();
  // mov %ds:offset_ptr, %eax
  code << 0x8b << ',' << 0x04 << ',' << 0x25 << ','
       << "{\"int32\":" << cmp_offset << "},";
  // and %eax, CMP_LIST_SIZE - 1  // make sure its value is b1111...
  code << 0x25 << ',' << "{\"int32\":" << CMP_LIST_SIZE - 1 << "},";
  // mov %eax %r10d
  code << 0x41 << ',' << 0x89 << ',' << 0xc2 << ',';
  // shl %r10d 5 (mul 32)
  code << 0x41 << ',' << 0xc1 << ',' << 0xe2 << ',' << 0x5 << ',';
  // add %eax, $0x01
  code << 0x83 << ',' << 0xc0 << ',' << 0x01 << ',';
  // mov %eax, %ds:offset_ptr
  code << 0x89 << ',' << 0x04 << ',' << 0x25 << ','
       << "{\"int32\":" << cmp_offset << "},";
  // code << "\"$fill_header\",";
  // mov $cmp_id cmp_area + %r10d + 16
  code << 0x67 << ',' << 0x41 << ',' << 0xc7 << ',' << 0x82 << ','
       << "{\"int32\":" << cmp_area_ptr + 16 << "},"
       << "\"$cmp_id\",";
  // mov $cmp_size cmp_area + %r10d + 20
  code << 0x67 << ',' << 0x41 << ',' << 0xc7 << ',' << 0x82 << ','
       << "{\"int32\":" << cmp_area_ptr + 20 << "},"
       << "\"$cmp_size\",";
  // mov $cmp_ty cmp_area + %r10d + 24
  code << 0x66 << ',' << 0x41 << ',' << 0xc7 << ',' << 0x82 << ','
       << "{\"int32\":" << cmp_area_ptr + 24 << "},"
       << "\"$cmp_ty\",";
#ifndef WINDOWS
  // mov %fs:0x50,%eax                    // mov stmt_index,%eax
  // code << 0x64 << ',' << 0x8b << ',' << 0x04 << ',' << 0x25 << ',' << 0x50
  //      << ',' << 0x00 << ',' << 0x00 << ',' << 0x00 << ',';

  // movl %ds:0x3b0108,%eax                    // mov stmt_index,%eax
  code << 0x8b << ',' << 0x04 << ',' << 0x25 << ',' << 0x08 << ',' << 0x01
       << ',' << 0x3b << ',' << 0x00 << ',';
#else
  //mov 0x47ff1000,%eax                    // mov stmt_index,%eax
  code << 0x8b << ',' << 0x04 << ',' << 0x25 << ',' << 0x00
       << ',' << 0x10 << ',' << 0xff << ',' << 0x47 << ',';
#endif
  // mov $stmt_index(%eax) cmp_area + %r10d + 26
  code << 0x66 << ',' << 0x41 << ',' << 0x89 << ',' << 0x82 << ','
       << "{\"int32\":" << cmp_area_ptr + 26 << "},";
  code << "\"$mov_operand0\",";
  code << restore_code.str();
  code << "\"$mov_operand1\",";
  code << "\"$mov_operand2\",";
  code << restore_code2.str();
  sendTrampolineMessage(cxt->out, "$trace", code.str().c_str()); 

  std::stringstream reg1_inst;
  reg1_inst << 0x67 << ',' << "\"$reg1_rex\"," << 0x89 << ','
            << "\"$reg1_mod\","
            << "{\"int32\":" << cmp_area_ptr << "},";
  sendTrampolineMessage(cxt->out, "$reg1_inst", reg1_inst.str().c_str());

  std::stringstream reg2_inst;
  reg2_inst << 0x67 << ',' << "\"$reg2_rex\"," << 0x89 << ','
            << "\"$reg2_mod\","
            << "{\"int32\":" << cmp_area_ptr + 8 << "},";
  sendTrampolineMessage(cxt->out, "$reg2_inst", reg2_inst.str().c_str());

  std::stringstream imm_inst;
  imm_inst << 0x67 << ',' << 0x41 << ','  // imm < 32 bits
           << 0xc7 << ',' << 0x82 << ',' << "\"$imm_disp\","
           << "\"$imm_val\",";
  sendTrampolineMessage(cxt->out, "$imm_inst", imm_inst.str().c_str());

  std::stringstream mem_inst;
  // push %r11
  mem_inst << 0x41 << ',' << 0x53 << ',';
  // mov %mem %r11
  mem_inst << "\"$mem_prefix\","
           << "\"$mem_rex\"," << "\"$mem_mov1\"," << "\"$mem_mod\","
           << "\"$mem_sib\","
           << "\"$mem_disp\",";
  // mov %r11 %cmp_area(%r10d)
  mem_inst << "\"$mem_prefix\"," 
           << "\"$mem_rex2\"," << "\"$mem_mov2\"," << 0x9a << ","
           << "\"$mem_dst\",";
  // pop %r11
  mem_inst << 0x41 << ',' << 0x5b << ',';
  sendTrampolineMessage(cxt->out, "$mem_inst", mem_inst.str().c_str());

  std::stringstream args_operand;
  // test %rdi %rdi
  args_operand << 0x48 << ','  << 0x85 << ',' << 0xff << ',';
  // jmp 
  args_operand << 0x74 << ",{\"rel8\":\".Lok3\"},";
  // mov [%rdi] %ax
  args_operand << 0x66 << ',' << 0x8b << ',' << 0x07 << ',';
  // mov %ax %cmp_area + %r10d + 28 (move its value to state(2bytes))
  args_operand << 0x66 << ',' << 0x41 << ',' << 0x89 << ',' << 0x82 << ','
                 << "{\"int32\":" << cmp_area_ptr + 28 << "},";
  args_operand << "\".Lok3\",";
  // test %rsi %rsi
  args_operand << 0x48 << ','  << 0x85 << ',' << 0xf6 << ',';
  // jmp 
  args_operand << 0x74 << ",{\"rel8\":\".Lok4\"},";
  // mov [%rdi] %ax
  args_operand << 0x66 << ',' << 0x8b << ',' << 0x06 << ',';
  // mov %ax %cmp_area + %r10d + 30 (move its value to state(2bytes))
  args_operand << 0x66 << ',' << 0x41 << ',' << 0x89 << ',' << 0x82 << ','
                 << "{\"int32\":" << cmp_area_ptr + 30 << "},";
  args_operand << "\".Lok4\",";

  // mov %rdi as operand1
  args_operand << 0x67 << ',' << 0x49 << ',' << 0x89 << ',' << 0xba << ','
                 << "{\"int32\":" << cmp_area_ptr << "},";
  sendTrampolineMessage(cxt->out, "$one_arg_operand",
                        args_operand.str().c_str());

  // mov %rsi as operand2
  args_operand << 0x67 << ',' << 0x49 << ',' << 0x89 << ',' << 0xb2 << ','
                 << "{\"int32\":" << cmp_area_ptr + 8 << "},";

  sendTrampolineMessage(cxt->out, "$two_arg_operand",
                        args_operand.str().c_str());

  // mov %edx %cmp_area(%r10d) + 20 (cmp_size)
  args_operand << 0x67 << ',' << 0x41 << ',' << 0x89 << ',' << 0x92 << ','
              << "{\"int32\":" << cmp_area_ptr + 20 << "},";
  sendTrampolineMessage(cxt->out, "$three_arg_operand", args_operand.str().c_str());
  return nullptr;
}

// find addr in plt table
void find_addr_in_plt(const ELF *elf, const char *name, CMP_TYPE type) {
  intptr_t addr = getELFPLTEntry(elf, name);
  if (addr != INTPTR_MIN) {
    log("find function %s at address: %#010x", name, addr);
    CmpPlt.insert({addr, type});
  } else {
    warn("Can't find function %s at plt!", name);
  }
}

// find addr in sym info
void find_addr_in_sym(const ELF *elf, const char *name, CMP_TYPE type) {
  SymbolInfo sym = getELFSymInfo(elf);
  for (auto iter = sym.begin(); iter != sym.end(); ++iter){
      if(!(strcmp(name,iter->first))){
        log("find function %s at address: %#010x", name, iter->second->st_value);
        CmpPlt.insert({iter->second->st_value, type});
        return;
      }
  }
  warn("Can't find function %s at sym!", name);
}

#ifndef WINDOWS
#define FIND_ADDR find_addr_in_plt
#else
#define FIND_ADDR find_addr_in_sym
#endif

/*
 * Events.
 */
extern void e9_plugin_event(const Context *cxt, Event event) {
  switch (event) {
    case EVENT_DISASSEMBLY_COMPLETE: {
#ifdef ENABLE_TRACE_STRCMP 
      const ELF *elf = cxt->elf;
      const PLTInfo info = getELFPLTInfo(elf);
      for (auto iter = info.begin(); iter != info.end(); ++iter) {
          log("plt func : %s, %p", iter->first, iter->second);
      }
      FIND_ADDR(elf, "strcmp", STRCMP);
      FIND_ADDR(elf, "strncmp", STRNCMP);
      FIND_ADDR(elf, "memcmp", MEMCMP);
#endif
      break;
    }
    // case EVENT_MATCHING_COMPLETE: {
    case EVENT_PATCHING_COMPLETE: {
      e9tool::warning("match cmp: %d (all: %d, bad: %d, opt: (%d, %d, %d)), fn: %d", num_patch_cmp, num_cmp, num_bad_cmp, num_opt1_cmp, num_opt2_cmp, num_opt3_cmp, num_fn_cmp);
      /*
      for (int i = 0; i < NUM_REG; i++) {
        if (reg_count[i]> 0)
          e9tool::warning("reg: %d, cnt: %d", i, reg_count[i]);
      }
      */
      break;
    }
    default:
      break;
  }
}

int32_t inst_operand_size(const Context *cxt) {
  int32_t operand_size = -1;
  Register reg = cxt->I->regs.read[0];
  if (reg == REGISTER_NONE || reg == REGISTER_INVALID) {
  } else if (reg <= REGISTER_R15B)
    operand_size = 1;
  else if (reg <= REGISTER_R15W)
    operand_size = 2;
  else if (reg <= REGISTER_EIP)
    operand_size = 4;
  else
    operand_size = 8;

  if (operand_size < 0) {
    operand_size = cxt->I->encoding.size.imm;
  }
  return operand_size;
}

intptr_t call_target(const InstrInfo *info) {
  return (intptr_t)info->address + (intptr_t)info->size +
         (intptr_t)info->op[0].imm;
}

bool is_r10(Register reg) {
  return reg == REGISTER_R10 || reg == REGISTER_R10B || reg == REGISTER_R10W ||
         reg == REGISTER_R10D;
}

bool is_r11(Register reg) {
  return reg == REGISTER_R11 || reg == REGISTER_R11B || reg == REGISTER_R11W ||
         reg == REGISTER_R11D;
}

bool is_rip(Register reg) {
  return reg == REGISTER_IP || reg == REGISTER_EIP || reg == REGISTER_RIP;
}

bool is_ebp(Register reg) {
  return reg == REGISTER_RBP || reg == REGISTER_EBP;
}

bool is_valid_reg(Register reg) {
  return reg != REGISTER_NONE && reg != REGISTER_EFLAGS && reg < NUM_REG;
}

int get_mem_off(MemOpInfo &mem_info) {
  int off = mem_info.disp;
  if (off < 0) off = 0 - off;
  return off;
}

void set_reg_taint(Register reg, bool flag) {
  reg_taint[reg] = flag;
  if (reg == REGISTER_RIP || reg == REGISTER_EIP || reg == REGISTER_IP || reg == REGISTER_EFLAGS) {
    return;
  }
  if (reg >= REGISTER_EAX) {
    reg_taint[reg - REGISTER_EAX + REGISTER_AX] = flag;
  }
  if (reg >= REGISTER_AX) {
    reg_taint[reg - REGISTER_AX + REGISTER_AL] = flag;
    if (reg <= REGISTER_BX) {
      reg_taint[reg - REGISTER_AX + REGISTER_AH] = flag;
    }
  }
}
/*
 * We match all control-flow transfer instructions.
 */
extern intptr_t e9_plugin_match(const Context *cxt) {
  // The e9_plugin_match() function is invoked once by E9Tool for each
  // disassembled instruction.  The function should return a value that is
  // used for matching.
  const InstrInfo* I = cxt->I;
  // e9tool::warning("%s", I->string.instr);
  switch (cxt->I->mnemonic) {
    /// simple intraprocedural data flow tracking
    case MNEMONIC_MOV: 
    case MNEMONIC_MOVQ:
    case MNEMONIC_MOVZX:
    // case MNEMONIC_XCHG:
    {
      if (!enable_sdft) return 0;
      OpInfo src_op = I->op[0];
      OpInfo dst_op = I->op[1];
      Register src_reg = src_op.reg;
      Register dst_reg = dst_op.reg;
      // e9tool::warning("%s, #reg: %d, reg0: %d, reg1: %d", I->string.instr, I->count.op, src_reg, dst_reg);
      // e9tool::warning("info: %d %d", op0_info.type, op1_info.type);
      if (dst_op.type == OPTYPE_REG && is_valid_reg(dst_reg)) {
        // reg's taint is clear by imm
        if (src_op.type == OPTYPE_IMM) {
          set_reg_taint(dst_reg, false);
          e9tool::debug("** clear reg %d by imm", dst_reg);
        } else if (src_op.type == OPTYPE_REG) {
          Register src_reg = src_op.reg;
          if (is_valid_reg(src_reg)) {
            set_reg_taint(dst_reg,  reg_taint[src_reg]);
          } else {
            // assume the other regs is untained
            set_reg_taint(dst_reg, false);
            e9tool::debug("** clear reg %d by reg %d", dst_reg, src_reg);
          }
        } else { // MEM
          MemOpInfo mem_info = src_op.mem;
          int off = get_mem_off(mem_info);
          // only consider local memory in stack
          if (is_ebp(mem_info.base) && off < STACK_FRAME_SIZE) {
            set_reg_taint(dst_reg, stack_taint[off]);
          } else {
            // assume the others is tainted.
            set_reg_taint(dst_reg, true);
          }
        }
      }
      if (dst_op.type == OPTYPE_MEM) {
        MemOpInfo mem_info = dst_op.mem;
        int off = get_mem_off(mem_info);
        if (is_ebp(mem_info.base) && off < STACK_FRAME_SIZE) {
          if (src_op.type == OPTYPE_IMM) { 
            stack_taint[off] = false; 
            e9tool::debug("** clear stack offset: %d", off);
          } else if (src_op.type == OPTYPE_REG) {
            if (is_valid_reg(src_reg)) {
              stack_taint[off] = reg_taint[src_reg]; 
            } else {
              // assme the other regs is untained
              stack_taint[off] = false;
              e9tool::debug("** clear stack %d by reg %d", off, src_reg);
            }
          } else {
            stack_taint[off] = true;
            e9tool::warning("** unknown instr: %s", I->string.instr);
          }
        }
      }
      return 0;
    }
    // clear any taint once meet binary mathmatical operations.
    // clear taint since it will modify values
    case MNEMONIC_ADC:
    case MNEMONIC_ADD:
    case MNEMONIC_XADD:
    case MNEMONIC_SUB:
    case MNEMONIC_SBB:
    case MNEMONIC_OR:
    case MNEMONIC_AND:
    case MNEMONIC_LEA:
    case MNEMONIC_SAR:
    case MNEMONIC_SARX:
    case MNEMONIC_SHR:
    case MNEMONIC_SHRX:
    case MNEMONIC_XOR: {
      if (!enable_sdft) return 0;
      if (I->count.op != 2) {
        e9tool::warning("unknown binary op: %s, #reg: %d, reg0: %d, reg1: %d", I->string.instr, I->count.op, I->op[0].reg, I->op[1].reg);
      }
      OpInfo dst_op = I->op[1];
      Register dst_reg = dst_op.reg;
      if (is_valid_reg(dst_reg)) {
        set_reg_taint(dst_reg, false);
        e9tool::debug("** clear reg %d by binary op", dst_reg);
      }
      return 0;
    }
    
    case MNEMONIC_DEC:
    case MNEMONIC_INC: {
      if (!enable_sdft) return 0;
      if (I->count.op != 1) {
        e9tool::warning("unknown binary op: %s, #reg: %d, reg0: %d, reg1: %d", I->string.instr, I->count.op, I->op[0].reg, I->op[1].reg);
      }
      OpInfo dst_op = I->op[0];
      Register dst_reg = dst_op.reg;
      if (is_valid_reg(dst_reg)) {
        set_reg_taint(dst_reg, false);
        e9tool::debug("** clear reg %d by binary op", dst_reg);
      }
      return 0;
    }
    // clear eax's taint once meet unitary mathmatical operations.
    case MNEMONIC_DIV:
    case MNEMONIC_IDIV:
    case MNEMONIC_MUL:
    case MNEMONIC_IMUL: {
      if (!enable_sdft) return 0;
      int num_op = I->count.op;
      // e9tool::warning("%s, #reg: %d, reg0: %d, reg1: %d", I->string.instr, num_op, I->op[0].reg, I->op[1].reg);
      OpInfo dst_op = I->op[1];
      if (num_op == 1) {
        // if (dst_op.reg != REGISTER_RAX && dst_op.reg != REGISTER_EAX && dst_op.reg != REGISTER_AX) {
        //    e9tool::warning("unknown binary op: %s, #reg: %d, reg0: %d, reg1: %d", I->string.instr, I->count.op, I->op[0].reg, I->op[1].reg);
        // }
      } else if (num_op == 2) {
        dst_op = I->op[1];
      } else if (num_op == 3) {
        dst_op = I->op[2];
      } else {
        e9tool::warning("** unknown instr: %s", I->string.instr);
        return 0;
      }
      Register dst_reg = dst_op.reg;
      if (is_valid_reg(dst_reg)) {
        set_reg_taint(dst_reg, false);
        e9tool::debug("** clear reg %d by mul/div", dst_reg);
      }
      return 0;
    }
    case MNEMONIC_PUSH: {
      if (!enable_sdft) return 0;
      // begin of function (may be)
      // Dyninst's trick, 0x55 (EBP/RBP) for elf x86
      // FIXME: stupid: since we do not consider any control flow
      Register reg0 = I->op[0].reg;
      if (is_ebp(reg0)) {
        for (int i = 0; i < NUM_REG; i++)
          reg_taint[i] = true;
        for (int i = 0; i < STACK_FRAME_SIZE; i++)
          stack_taint[i] = true;
      }
      return 0;
    }
    case MNEMONIC_POP: {
      return 0;
    }
    case MNEMONIC_CMP: {
      // e9tool::warning("cmp: %s", I->string.instr);
      int32_t operand_size = I->op[0].size;
      if (!enable_cmp_one_byte && operand_size == 1) {
        log("ignore instruction for compare one byte: %s", I->string.instr);
        return 0;
      }
      bool has_imm = I->hasIMM();
      int64_t imm = I->getIMM();
      if (operand_size == 0 || (has_imm && (imm == 0 || imm == 1 || imm < INT32_MIN || imm > INT32_MAX))) {
        log("ignore instruction with useless imm: %s", I->string.instr);
        return 0;
      }
      // Ignore cmp uses r10 or r11\rip
      int taint_cnt = 0;
      bool reg_valid = true;
      for (int i = 0; i < 2; i++) {
        OpInfo op_info = I->op[i];
        if (op_info.type == OPTYPE_REG) {
          Register reg = op_info.reg;
          if (!is_valid_reg(reg) || is_rip(reg) || is_r10(reg)) {
            reg_valid = false;
            continue;
          }
          reg_count[reg] += 1;
          if (reg_taint[reg]) {
            taint_cnt += 1;
          }
        } else if (op_info.type == OPTYPE_IMM) {
          if (!I->hasIMM()) {
            e9tool::warning("op is imm but does not has IMM: %s ", I->string.instr);
            return 0;
          }
        } else if (op_info.type == OPTYPE_MEM) {
          MemOpInfo mem_info = op_info.mem;
          reg_count[mem_info.base] += 1;
          reg_count[mem_info.index] += 1;
          if (is_r10(mem_info.base) || is_r10(mem_info.index) ||
            is_r11(mem_info.base) || is_r11(mem_info.index) || is_rip(mem_info.base) || is_rip(mem_info.index)) {
            reg_valid = false;
            continue;
          }
          if (is_ebp(mem_info.base)) {
            int off = get_mem_off(mem_info);
            // skip if stack is not tainted
            if (off < STACK_FRAME_SIZE && !stack_taint[off]) {
              continue;
            }
          } 
          // assume memory has taint
          taint_cnt += 1;
        } else {
          return 0;
        }
      }
      num_cmp += 1;
      if (I->size < 5) {
        e9tool::debug("cmp size < 5");
        num_bad_cmp += 1;
      } 
      if (!reg_valid) {
        e9tool::debug("** ignore reg invalid cmp: %s", I->string.instr);
        num_opt1_cmp += 1;
        return 0;
      }
      if (enable_sdft && taint_cnt == 0) {
        e9tool::debug("** ignore no taint cmp: %s", I->string.instr);
        num_opt2_cmp += 1;
        return 0;
      }
      int32_t id = I->offset;
      if (std::find(blacklist_ids.begin(), blacklist_ids.end(), id) != blacklist_ids.end() ) {
        num_opt3_cmp += 1;
        return 0;
      }
      num_patch_cmp += 1;
      return INSTCMP;
    }
    case MNEMONIC_CALL: {
#ifdef ENABLE_TRACE_STRCMP
      if (I->op[0].type == OPTYPE_IMM) {
        intptr_t target = call_target(I);
        auto f = CmpPlt.find(target);
        if (f != CmpPlt.end()) {
          // fprintf(stderr, "the function is %d type", ty);
          int32_t id = cxt->I->offset;
          if (std::find(blacklist_ids.begin(), blacklist_ids.end(), id) != blacklist_ids.end() ) {
            return 0;
          }
          num_fn_cmp += 1;
          return f->second;
        }
      }
#endif
      return 0;
    }
    // SIMD, Packed Double-Precision Floating-Point Values
    case MNEMONIC_CMPPD:
    case MNEMONIC_CMPPS:
      return 0;
    // Compare String Operands
    case MNEMONIC_CMPSB:
    case MNEMONIC_CMPSD:
    case MNEMONIC_CMPSQ:
    case MNEMONIC_CMPSS:
    case MNEMONIC_CMPSW:
      return 0;
    // MNEMONIC_CMPXCHG,
    // MNEMONIC_CMPXCHG16B,
    // MNEMONIC_CMPXCHG8B,
    case MNEMONIC_COMISD:
    case MNEMONIC_COMISS:
      return 0;
    default:
      return 0;
  }
}

/*
 * Emit the patch template code.
 */
extern void e9_plugin_code(const Context *cxt) {
    // The e9_plugin_code() function is invoked once by E9tool.
    // The function specifies the "code" part of the trampoline template that
    // will be executed for each matching instruction.`
    fputs("\"$trace\",", cxt->out);
}

/*
 * Emit the patch template data.
 */
extern void e9_plugin_data(const Context *cxt)
{
    // The e9_plugin_code() function is invoked once by E9tool.
    // The function specifies the "data" part of the trampoline template that
    // will be attached to each matching instruction.

    // In this example, there is no data so this function does nothing.
    // The function could also be removed from the plugin.
}

// get register reference for mod
uint8_t get_reg_mod(Register reg) {
  switch (reg) {
    case REGISTER_AH:
    case REGISTER_AL:
    case REGISTER_AX:
    case REGISTER_EAX:
    case REGISTER_RAX:
    case REGISTER_R8B:
    case REGISTER_R8W:
    case REGISTER_R8D:
    case REGISTER_R8:
      return 0;
    case REGISTER_CH:
    case REGISTER_CL:
    case REGISTER_CX:
    case REGISTER_ECX:
    case REGISTER_RCX:
    case REGISTER_R9B:
    case REGISTER_R9W:
    case REGISTER_R9D:
    case REGISTER_R9:
      return 1;
    case REGISTER_DH:
    case REGISTER_DL:
    case REGISTER_DX:
    case REGISTER_EDX:
    case REGISTER_RDX:
    case REGISTER_R10B:
    case REGISTER_R10W:
    case REGISTER_R10D:
    case REGISTER_R10:
      return 2;
    case REGISTER_BH:
    case REGISTER_BL:
    case REGISTER_BX:
    case REGISTER_EBX:
    case REGISTER_RBX:
    case REGISTER_R11B:
    case REGISTER_R11W:
    case REGISTER_R11D:
    case REGISTER_R11:
      return 3;
    case REGISTER_SPL:
    case REGISTER_SP:
    case REGISTER_ESP:
    case REGISTER_RSP:
    case REGISTER_R12B:
    case REGISTER_R12W:
    case REGISTER_R12D:
    case REGISTER_R12:
      return 4;
    case REGISTER_BPL:
    case REGISTER_BP:
    case REGISTER_EBP:
    case REGISTER_RBP:
    case REGISTER_R13B:
    case REGISTER_R13W:
    case REGISTER_R13D:
    case REGISTER_R13:
      return 5;
    case REGISTER_SIL:
    case REGISTER_SI:
    case REGISTER_ESI:
    case REGISTER_RSI:
    case REGISTER_R14B:
    case REGISTER_R14W:
    case REGISTER_R14D:
    case REGISTER_R14:
      return 6;
    case REGISTER_DIL:
    case REGISTER_DI:
    case REGISTER_EDI:
    case REGISTER_RDI:
    case REGISTER_R15B:
    case REGISTER_R15W:
    case REGISTER_R15D:
    case REGISTER_R15:
      return 7;
  }
  return 0;
}

/*
 * Patch the selected instructions.
 */
extern void e9_plugin_patch(const Context *cxt) {
  // The e9_plugin_patch() function is invoked by E9Tool once per
  // matching instruciton.  The function specifies the "metadata" which
  // instantiates any macros in the trampoline template (both code or data).
  // The metadata is specified in as comma-seperated "$key":VALUE pairs,
  // where $key is a macro name and VALUE is a value in the template
  // template format.
  //
  // https://gist.github.com/mikesmullin/6259449
  // [PREFIX] [OP] [MOD-REG] [SIB] [DISP] [IMM]
  // [REX Prefix] : 0b0100 WRXB
  //      W=1: 64-bit operand size,
  //      R/X/B=1: map registers R8-R15 in MODRM.(R)eg / SIB.inde(X) / MODRM.rm
  //      and SIB.(B)ase
  // [Mod-Reg R/M] :
  //      2-bits (0-4) : MODRM.mod
  //      3-bits (0-7) : MODRM.reg (reg/opcode)
  //      3-bits (0-7) : MODRM.rm (register/memory)
  // The Memory Address Operand: Mod-Reg R/M	+ SIB + Displacement(Optional)
  //      Scale-Index-Base (SIB): Scale(2bit) - Index(3bit) - Base(3bit)
  //      Real Address = Segment + SIB.base + (SIB.index × SIB.scale) +
  //      Displacement
  // r10: 010, r11: 011

  // intptr_t kind = e9_plugin_match(cxt);
  int32_t id = cxt->I->offset; //++hopper_cmp_counter; 
  if (cxt->I->mnemonic == MNEMONIC_CMP) {
    int16_t operand_size = cxt->I->op[0].size;
    uint8_t rex = cxt->I->getREX();
    uint8_t mod = cxt->I->getMODRM();
    log("cmp id: %d, addr: %x, op %s, size: %d, regs: %d(%d) %d(%d) rex: 0x%02X, mod: "
        "0x%02X, sib: 0x%02X, disp: %#010x, imm: %#010x",
        id, cxt->I->address, cxt->I->string.instr, operand_size, cxt->I->regs.read[0],
        cxt->I->op[0].type, cxt->I->regs.read[1], cxt->I->op[1].type, rex, mod,
        cxt->I->getSIB(), cxt->I->getDISP(), cxt->I->getIMM());

    fprintf(cxt->out, "\"$cmp_id\":{\"int32\":%d},", id);
    fprintf(cxt->out, "\"$cmp_size\":{\"int32\":%d},", operand_size);
    fprintf(cxt->out, "\"$cmp_ty\":{\"int16\":%d},", INSTCMP);
    fprintf(cxt->out, "\"$mov_operand0\":null,");

    int num_reg = 0;
    // regs
    for (int i = 0; i < 2; i++) {
      OpInfo op_info = cxt->I->op[i];
      int arg_i = i + 1;
      int32_t operand_addr = INSTR_AREA + 8 * i;
      if (op_info.type == OPTYPE_REG) {
        Register reg = op_info.reg;
        num_reg++;
        if (reg == REGISTER_NONE || reg == REGISTER_INVALID || is_r10(reg)) {
          log("ignore r10, fill empty for %d-th arg", arg_i);
          fprintf(cxt->out, "\"$mov_operand%d\":null,", arg_i);
          continue;
        }
        log("use reg %d as %d-th arg", reg, arg_i);
        fprintf(cxt->out, "\"$mov_operand%d\":\"$reg%d_inst\",", arg_i, arg_i);
        uint8_t new_rex = 0x41;  // base is r10
        if (reg >= REGISTER_RAX) {
          // W field is enable: 64bit
           new_rex |= 0x8;
        }
        if ((reg >= REGISTER_R8B && reg <= REGISTER_R15B) || (reg >= REGISTER_R8W && reg <= REGISTER_R15W) 
            || (reg >= REGISTER_R8D && reg <= REGISTER_R15D) || (reg >= REGISTER_R8 && reg <= REGISTER_R15)) {
              // R field is enable, to map registers R8-R15
              new_rex |= 0x4;
        }
        fprintf(cxt->out, "\"$reg%d_rex\":%d,", arg_i, new_rex);
        log("rex:0x%02X, new_rex: 0x%02X", rex, new_rex);
        uint8_t new_mod = (get_reg_mod(reg) << 3) | 0x82;
        log("mode: 0x%02X, new_mod: 0x%02X", mod, new_mod);
        fprintf(cxt->out, "\"$reg%d_mod\":%d,", arg_i, new_mod);
      } else if (op_info.type == OPTYPE_IMM && cxt->I->hasIMM()) {
        int64_t imm = cxt->I->getIMM();
        log("use imm %lld as %d-th arg", imm, arg_i);
        fprintf(cxt->out, "\"$mov_operand%d\":\"$imm_inst\",", arg_i);
        fprintf(cxt->out, "\"$imm_disp\":{\"int32\":%d},", operand_addr);
        fprintf(cxt->out, "\"$imm_val\":{\"int32\":%ld},", imm);
      } else if (op_info.type == OPTYPE_MEM) {
        // check r10, r11
        MemOpInfo mem_info = op_info.mem;
        if (is_r10(mem_info.base) || is_r10(mem_info.index) ||
            is_r11(mem_info.base) || is_r11(mem_info.index)) {
          log("ignore r10 or r11, fill empty for %d-th arg", arg_i);
          fprintf(cxt->out, "\"$mov_operand%d\":null,", arg_i);
          continue;
        }
        if (is_rip(mem_info.base) || is_rip(mem_info.index)) {
          log("ignore rip, fill empty for %d-th arg", arg_i);
          fprintf(cxt->out, "\"$mov_operand%d\":null,", arg_i);
          continue;
        }
        log("fill mem for %d-th arg", arg_i);
        fprintf(cxt->out, "\"$mov_operand%d\":\"$mem_inst\",", arg_i);
        int rex_offset = cxt->I->encoding.offset.rex;
        // WORD PTR requires a legacy prefix of 0x66
        if (op_info.size == 2) {
          fprintf(cxt->out, "\"$mem_prefix\":%d,", 0x66);
        } else {
          fprintf(cxt->out, "\"$mem_prefix\":null,");
        }
        // rex should support r11
        uint8_t rex = cxt->I->getREX() | 0x44 ;
        // QWORD PTR requires REX.W enabled
        if (op_info.size == 8) {
          rex |= 0x48;
        }
        fprintf(cxt->out, "\"$mem_rex\":%d,", rex);
        fprintf(cxt->out, "\"$mem_rex2\":%d,", rex | 0x41);
        if (op_info.size == 1) {
          // 0x8a for mov BYTE PTR
          fprintf(cxt->out, "\"$mem_mov1\":%d,", 0x8a);
          fprintf(cxt->out, "\"$mem_mov2\":%d,", 0x88);
        } else {
          // 0x8b for others
          fprintf(cxt->out, "\"$mem_mov1\":%d,", 0x8b);
          fprintf(cxt->out, "\"$mem_mov2\":%d,", 0x89);
        }
        // change reg to r11
        // memory bits in mod must in r/m (last 3 bits)
        uint8_t new_mod = (mod & 0xC7) | 0x18;
        fprintf(cxt->out, "\"$mem_mod\":%d,", new_mod);
        if (cxt->I->hasSIB())
          fprintf(cxt->out, "\"$mem_sib\":%d,", cxt->I->getSIB());
        else
          fprintf(cxt->out, "\"$mem_sib\":null,");
        int disp_size = cxt->I->encoding.size.disp;
        int32_t disp = cxt->I->getDISP();
        if (disp_size == 1)
          fprintf(cxt->out, "\"$mem_disp\":{\"int8\":%d},", disp);
        else if (disp_size == 4)
          fprintf(cxt->out, "\"$mem_disp\":{\"int32\":%d},", disp);
        else
          fprintf(cxt->out, "\"$mem_disp\":null,");
        fprintf(cxt->out, "\"$mem_dst\":{\"int32\":%d},", operand_addr);
      } else {  // fill empty
        log("fill empty for %d-th arg", arg_i);
        fprintf(cxt->out, "\"$mov_operand%d\":null,", arg_i);
      }
    }
  } else if (cxt->I->mnemonic == MNEMONIC_CALL) {
#ifdef ENABLE_TRACE_STRCMP
    intptr_t target = call_target(cxt->I);
    auto f = CmpPlt.find(target);
    CMP_TYPE kind = f->second;
    log("id: %d, fn %s, ty: %d", id, cxt->I->string.instr, kind);
    fprintf(cxt->out, "\"$cmp_id\":{\"int32\":%d},", id);
    fprintf(cxt->out, "\"$cmp_ty\":{\"int16\":%d},", kind);
    fprintf(cxt->out, "\"$cmp_size\":{\"int32\":%d},", 0);
    if (kind == STRCMP) {
      fprintf(cxt->out, "\"$mov_operand0\":\"$two_arg_operand\",");
    } else if (kind == STRNCMP || kind == MEMCMP) {
      fprintf(cxt->out, "\"$mov_operand0\":\"$three_arg_operand\",");
    }
    fprintf(cxt->out, "\"$mov_operand1\":null,");
    fprintf(cxt->out, "\"$mov_operand2\":null,");
#endif
  }
}

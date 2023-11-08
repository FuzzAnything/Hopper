#ifndef _HAVE_COMMON_CONFIG_H
#define _HAVE_COMMON_CONFIG_H

#ifndef MAP_SIZE_POW2
#define MAP_SIZE_POW2 16
#endif
#define MAP_SIZE ((size_t)1 << MAP_SIZE_POW2)

// coverage
#ifndef WINDOWS
#define AREA_BASE 0x200000
#else
#define AREA_BASE 0x47E00000
#endif
#define AREA_SIZE MAP_SIZE
#define AREA_POINTER ((uint8_t *)AREA_BASE)

// cmp and mem
#define INSTR_AREA (AREA_BASE + 0x100000)
#define CMP_AREA INSTR_AREA
#define CMP_AREA_SIZE 0x80000
#define CMP_LIST_SIZE (CMP_AREA_SIZE / 32)
#define MEM_AREA (INSTR_AREA + CMP_AREA_SIZE)
#define MEM_AREA_SIZE 0x30000
#define MEM_LIST_SIZE (MEM_AREA_SIZE / 24)
#define INSTR_AREA_SIZE (CMP_AREA_SIZE + MEM_AREA_SIZE)
#define INFO_AREA (INSTR_AREA + INSTR_AREA_SIZE)
#define INSTR_INFO_SIZE 64
#define INSTR_ALL_SIZE (INSTR_AREA_SIZE + INSTR_INFO_SIZE)
#define INSTR_AREA_POINTER ((uint64_t *)INSTR_AREA)

// for canary
#define CANARY_PTR (INSTR_AREA + 0x100000)
#define CANARY_AREA_SIZE 0x100000

#ifndef WINDOWS
#define arg1 rdi
#define arg2 rsi
#else 
#define arg1 rcx
#define arg2 rdx
#endif

#endif /* ! _HAVE_DEFS_H */

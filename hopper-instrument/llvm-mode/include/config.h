#ifndef _HAVE_LLVM_CONFIG_H
#define _HAVE_LLVM_CONFIG_H

#ifndef MAP_SIZE_POW2
#define MAP_SIZE_POW2 16
#endif
#ifdef HOPPER_MAP_SIZE_POW2
#define MAP_SIZE_POW2 HOPPER_MAP_SIZE_POW2
#endif
#define MAP_SIZE ((size_t)1 << MAP_SIZE_POW2)


#include <stdint.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#endif /* ! _HAVE_DEFS_H */
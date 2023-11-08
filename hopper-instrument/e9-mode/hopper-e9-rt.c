// e9loader is under the MIT license.
#include "e9loader.h"
#include "config.h"

typedef struct __attribute__((__packed__)) MemOperation {
  uint64_t addr;
  uint32_t id;
  uint16_t ty;
  uint16_t stmt_index;
  uint32_t size;
  uint32_t slice;
} MemOperation;

enum MEM_TYPE {
  FREE = 1,
  MALLOC,
  CALLOC,
  REALLOC,
  REALLOC_MALLOC,
  REALLOC_FREE,
  REALLOC_RESIZE,
  OPEN = 90,
  FDOPEN,
  LSEEK,
  READ,
  WRITE,
  CLOSE,
};

MemOperation *mem_area_ptr = (MemOperation *)MEM_AREA;
int32_t *mem_offset_ptr = (int32_t *)(INFO_AREA + 4);
const int16_t *stmt_index_ptr = (int16_t *)(INFO_AREA + 8);
int64_t *free_ptr = (int64_t *)(INFO_AREA + 16);
int64_t *malloc_ptr = (int64_t *)(INFO_AREA + 24);
int64_t *calloc_ptr = (int64_t *)(INFO_AREA + 32);
int64_t *realloc_ptr = (int64_t *)(INFO_AREA + 40);

int32_t get_mem_offset() {
  int32_t offset = *mem_offset_ptr;
  *mem_offset_ptr = offset == MEM_LIST_SIZE - 1 ? 0 : offset + 1;
  return offset;
}

#ifndef WINDOWS
#include "rt-linux.c"
#define log(msg, ...) \
  print_message(false, "e9afl log: " msg "\n", ##__VA_ARGS__)
#else
#include "rt-win.c"
#define log(msg, ...)
#endif

void *libc_memset(void *dstpp, int c, size_t len) {
#define op_t unsigned int long
#define OPSIZ (sizeof(op_t))
  typedef unsigned char byte;
  long int dstp = (long int)dstpp;

  if (len >= 8) {
    size_t xlen;
    op_t cccc;

    cccc = (byte)c;
    cccc |= cccc << 8;
    cccc |= cccc << 16;
    if (OPSIZ > 4)
      /* Do the shift in two steps to avoid warning if long has 32 bits.  */
      cccc |= (cccc << 16) << 16;

    /* There are at least some bytes to set.
   No need to test for LEN == 0 in this alignment loop.  */
    while (dstp % OPSIZ != 0) {
      ((byte *)dstp)[0] = c;
      dstp += 1;
      len -= 1;
    }

    /* Write 8 `op_t' per iteration until less than 8 `op_t' remain.  */
    xlen = len / (OPSIZ * 8);
    while (xlen > 0) {
      ((op_t *)dstp)[0] = cccc;
      ((op_t *)dstp)[1] = cccc;
      ((op_t *)dstp)[2] = cccc;
      ((op_t *)dstp)[3] = cccc;
      ((op_t *)dstp)[4] = cccc;
      ((op_t *)dstp)[5] = cccc;
      ((op_t *)dstp)[6] = cccc;
      ((op_t *)dstp)[7] = cccc;
      dstp += 8 * OPSIZ;
      xlen -= 1;
    }
    len %= OPSIZ * 8;

    /* Write 1 `op_t' per iteration until less than OPSIZ bytes remain.  */
    xlen = len / OPSIZ;
    while (xlen > 0) {
      ((op_t *)dstp)[0] = cccc;
      dstp += OPSIZ;
      xlen -= 1;
    }
    len %= OPSIZ;
  }

  /* Write the last few bytes.  */
  while (len > 0) {
    ((byte *)dstp)[0] = c;
    dstp += 1;
    len -= 1;
  }

  return dstpp;
}

// TODO: mmap / munmap

void entry_free(uint32_t id, int64_t *arg1) {
  int64_t addr = *arg1;
  if (addr == 0) return;
  int32_t offset = get_mem_offset();
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = 0;
  mem_area_ptr[offset].addr = addr;
  mem_area_ptr[offset].ty = FREE;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  // log("id: %d, free : %p", id,  mem_area_ptr[offset].addr);
  // these pointers is alloc via mmap
  if (addr >= CANARY_PTR && addr <= CANARY_PTR + CANARY_AREA_SIZE) {
    *arg1 = 0;
  }
  // *arg1 = 0;
}

void entry_malloc(uint32_t id, int64_t arg1) {
  int32_t offset = get_mem_offset();
  // log("%d-malloc : %d, %d", offset, id, arg1);
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = arg1;
  mem_area_ptr[offset].ty = MALLOC;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  mem_area_ptr[offset].addr = 0;
}

void entry_calloc(uint32_t id, int64_t arg1, int64_t arg2) {
  int32_t offset = get_mem_offset();
  // log("%d-calloc : %d, %d, %d", offset, id, arg1, arg2);
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = arg1 * arg2;
  mem_area_ptr[offset].ty = CALLOC;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  mem_area_ptr[offset].addr = 0;
}

void entry_realloc(uint32_t id, int64_t arg1, int64_t arg2) {
  // we assmue canary's pointer won't be realloc
  int32_t offset = get_mem_offset();
  // log("%d-realloc : %d, %d, %d", offset, id, arg1, arg2);
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].addr = arg1;
  mem_area_ptr[offset].size = arg2;
  mem_area_ptr[offset].ty = REALLOC;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

void entry_indirect(uint32_t id, int64_t addr, int64_t *arg1, int64_t arg2) {
  // log("id: %d, indirect, addr: %p, arg1 : %p, arg2: %p", id, addr, *arg1,
  // arg2);
  if (addr == *free_ptr) {
    entry_free(id, arg1);
  } else if (addr == *malloc_ptr) {
    entry_malloc(id, *arg1);
  } else if (addr == *calloc_ptr) {
    entry_calloc(id, *arg1, arg2);
  } else if (addr == *realloc_ptr) {
    entry_realloc(id, *arg1, arg2);
  }
}

void exit_malloc(uint32_t id, int64_t rax) {
  int32_t offset = *mem_offset_ptr - 1;
  // log("%d-malloc-exit : %d, %d", offset, id, rax);
  // not thread safe
  if (id - mem_area_ptr[offset].id < 8) {
    mem_area_ptr[offset].addr = rax;
    libc_memset((void *)rax, 0xFA, mem_area_ptr[offset].size);
  }
}

void exit_calloc(uint32_t id, int64_t rax) {
  int32_t offset = *mem_offset_ptr - 1;
  // log("%d-malloc-exit : %d, %d", offset, id, rax);
  // not thread safe
  if (id - mem_area_ptr[offset].id < 8) {
    mem_area_ptr[offset].addr = rax;
  }
}

void exit_realloc(uint32_t id, int64_t rax) {
  int32_t offset = *mem_offset_ptr - 1;
  // log("%d-realloc-exit : %d, %d", offset, id, rax);
  if (mem_area_ptr[offset].ty != REALLOC) {
#ifndef WINDOWS
    error("should be realloc but find %d, id: %d", mem_area_ptr[offset].ty, id);
#endif
  }
  if (id - mem_area_ptr[offset].id < 8) {
    int64_t prev_addr = mem_area_ptr[offset].addr;
    if (rax != prev_addr) {
      if (prev_addr == 0) {
        // like malloc
        mem_area_ptr[offset].addr = rax;
        mem_area_ptr[offset].ty = REALLOC_MALLOC;
      } else if (rax == 0) {
        // like free
        mem_area_ptr[offset].ty = REALLOC_FREE;
      } else {
        uint64_t size = mem_area_ptr[offset].size;
        // free
        mem_area_ptr[offset].size = 0;
        mem_area_ptr[offset].ty = REALLOC_FREE;
        // malloc
        uint64_t id = mem_area_ptr[offset].id;
        int32_t offset = get_mem_offset();
        mem_area_ptr[offset].id = id;
        mem_area_ptr[offset].addr = rax;
        mem_area_ptr[offset].size = size;
        mem_area_ptr[offset].ty = REALLOC_MALLOC;
        mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
      }
    } else {
      // do nothing, but should update its size
      mem_area_ptr[offset].ty = REALLOC_RESIZE;
    }
  }
}

void exit_indirect(uint32_t id, int64_t rax) {
  int32_t offset = *mem_offset_ptr - 1;
  if (id - mem_area_ptr[offset].id < 8) {
    switch (mem_area_ptr[offset].ty) {
      case MALLOC:
        exit_malloc(id, rax);
        break;
      case CALLOC:
        exit_calloc(id, rax);
        break;
      case REALLOC:
        exit_realloc(id, rax);
        break;
    }
  }
}

// get suffix of filename
void set_file_name_suffix(char *filename, char *suffix) {
  int len = 0;
  int start = 0;
  for (int i =0; i < 256; i++) {
    // if it is '/'
    if (filename[i] == 47) start = i + 1;
    if (filename[i] == 0) {
      len = i;
      break;
    }
  }
  if (len > 4 && start < len - 4) start = len - 4;
  //printf("file: %s, start: %d, end: %d\n", filename, start, len);
  for (int i = 0; i < 4; i++) {
    int j = start + i;
    if (filename[j] == 0 || j >= len) break;
    suffix[i] = filename[j];
  }
}

// FILE *fopen( const char *filename, const char *mode );
// FILE *fopen( const char *restrict filename, const char *restrict mode );
// errno_t fopen_s( FILE *restrict *restrict streamptr, const char *restrict
// filename, const char *restrict mode );
void entry_fopen(uint32_t id, int64_t arg1, int64_t arg2) {
  // if (arg1 == 0 || arg2 == 0) {
  //   return;
  // }
  int32_t offset = get_mem_offset();
  const char *mode = (const char *)arg2;
  // write
  int read_mode = 2;
  // read
  for (int i = 0; i < 4; i++) {
    if (mode[i] == 0) break;
    if (mode[i] == 'r' || mode[i] == '+') read_mode = 1;
  }
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = read_mode;
  mem_area_ptr[offset].addr = arg1;
  mem_area_ptr[offset].ty = OPEN;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  // we save the prefix of filename to avoid that the filename is copy and
  // modify in the execution.
  set_file_name_suffix((char *)arg1, (char *)&mem_area_ptr[offset].slice);
}

/*
FILE *freopen( const char *filename, const char *mode,
               FILE *stream );
(until C99)
FILE *freopen( const char *restrict filename, const char *restrict mode,
               FILE *restrict stream );
(since C99)
errno_t freopen_s( FILE *restrict *restrict newstreamptr,
                   const char *restrict filename, const char *restrict mode,
                   FILE *restrict stream );
*/
void hook_malloc(uint32_t id, int64_t arg1, int64_t *ret) {
  entry_malloc(id, arg1);
  void *(*f)(size_t) = (void *(*)(size_t)) * malloc_ptr;
  *ret = (int64_t)f((size_t)arg1);
  exit_malloc(id, *ret);
}

void hook_calloc(uint32_t id, int64_t arg1, int64_t arg2, int64_t *ret) {
  entry_calloc(id, arg1, arg2);
  void *(*f)(size_t, size_t) = (void *(*)(size_t, size_t)) * calloc_ptr;
  *ret = (int64_t)f((size_t)arg1, (size_t)arg2);
  exit_calloc(id, *ret);
}

void hook_realloc(uint32_t id, int64_t arg1, int64_t arg2, int64_t *ret) {
  entry_realloc(id, arg1, arg2);
  void *(*f)(size_t, size_t) = (void *(*)(size_t, size_t)) * realloc_ptr;
  *ret = (int64_t)f((size_t)arg1, (size_t)arg2);
  exit_realloc(id, *ret);
}
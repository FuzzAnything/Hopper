// stdlib.c is under the MIT license.
#include "stdlib.c"

static FILE *log = NULL;

static void print_message(bool fatal, const char *msg, ...) {
  va_list ap;
  va_start(ap, msg);
  if (log == NULL) {
    log = fopen("/tmp/e9afl.log", "a");
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

#define error(msg, ...) \
  print_message(true, "e9afl runtime error: " msg "\n", ##__VA_ARGS__)
#define log(msg, ...) \
  print_message(false, "e9afl log: " msg "\n", ##__VA_ARGS__)

/* Init TLS if necessary. */
#include <asm/prctl.h>
static void __afl_init_tls(void) {
  uintptr_t val;
  int r = (int)syscall(SYS_arch_prctl, ARCH_GET_FS, &val);
  if (r < 0) error("failed to get TLS base address: %s", strerror(errno));
  if (val == 0x0) {
    /*
     * If glibc is not dynamically linked then %fs may be uninitialized.
     * Since the instrumentation uses TLS, this will cause the binary to
     * crash.  We fix this using a "dummy" TLS.
     */
    static uint8_t dummy_tls[128] = {0};
    r = (int)syscall(SYS_arch_prctl, ARCH_SET_FS,
                     dummy_tls + sizeof(dummy_tls));
    if (r < 0) error("failed to set TLS base address: %s", strerror(errno));
  }
}

/*
 * Init.
 */
void init(int argc, const char **argv, char **envp, void *dynamic,
          const struct e9_config_s *config) {
  log("fuzzing binary %s", argv[0]);
  __afl_init_tls();
  if ((config->flags & E9_FLAG_EXE) == 0) {
    /*
     * This is a shared library.  For this, we set up a dummy area so the
     * instrumentation does not crash during program initialization.  The
     * main executable is responsible for setting up AFL proper.
     */
    void *p1 = mmap(AREA_POINTER, AREA_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    void *p2 = mmap(INSTR_AREA_POINTER, INSTR_ALL_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    // try disable coverage
    __asm__("movl $0xFFFFFFFF, %ds:0x3B0100;");

    log("init lib done, mmap ptr: %p, %p!", p1, p2);

    /*
    // since shared binary is not linked with libc,
    // so we can't find dl* 's sym and can't init it.
    if (dlinit(dynamic) != 0)
    {
        fprintf(stderr, "dlinit() failed: %s\n", strerror(errno));
        abort();
    }
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    void* free_ptr = dlsym(handle, "free");
    log("free ptr: %p", free_ptr);
    */
    return;
  }
  log("init exe done!");
  environ = envp;
}

/*
 * Entry.  This is a (slower) alternative to the plugin instrumentation.
 *
 * USAGE:
 *      E9AFL_NO_INSTRUMENT=1 ./e9tool -M 'plugin(e9afl).match()' \
 *               -P 'entry(random)@"hopper-e9-rt"' \
 *               path/to/binary
 */
void entry(uint32_t curr_loc) {
  uint32_t prev_loc = 0;
  asm("mov %%ds:0x3B0100,%0" : "=r"(prev_loc));
  uint16_t idx = prev_loc ^ curr_loc;
  AREA_POINTER[idx]++;
  asm("mov %0,%%ds:0x3B0100" : : "r"(curr_loc >> 1));
}

extern void set_file_name_suffix(char *filename, char *prefix);

// int open(const char *pathname, int flags);
// int open(const char *pathname, int flags, mode_t mode);
// int open64 (const char *file, int oflag, ...)
void entry_open(uint32_t id, int64_t arg1, int32_t arg2) {
  // log("open %lld, %d", arg1, arg2);
  // if (arg1 == 0) {
  //   return;
  // }
  int32_t offset = get_mem_offset();
  int read_mode = 1;
  // O_WRONLY        00000001
  if ((arg2 & 1) > 0) {
    read_mode = 2;
  }
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = read_mode;
  mem_area_ptr[offset].addr = arg1;
  mem_area_ptr[offset].ty = OPEN;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  set_file_name_suffix((char *)arg1, (char *)&mem_area_ptr[offset].slice);
}

// int creat(const char *pathname, mode_t mode);
void entry_creat(uint32_t id, int64_t arg1) {
  // if (arg1 == 0) {
  //   return;
  // }
  int32_t offset = get_mem_offset();
  // create is O_WRONLY
  int read_mode = 2;
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = read_mode;
  mem_area_ptr[offset].addr = arg1;
  mem_area_ptr[offset].ty = OPEN;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
  set_file_name_suffix((char *)arg1, (char *)&mem_area_ptr[offset].slice);
}

#define IS_RESERVED_FD(fd) (fd >=3 && fd <= 32)

// FILE *fdopen(int fd, const char *mode);
void entry_fdopen(uint32_t id, int32_t *arg1, int64_t arg2) {
  int32_t offset = get_mem_offset();
  const char *mode = (const char *)arg2;
  // write
  int read_mode = 2;
  // read
  for (int i = 0; i < 4; i++) {
    if (mode[i] == 0) break;
    if (mode[i] == 'r' || mode[i] == '+') read_mode = 1;
  }
  int fd = *arg1;
  // log("fdopen %d, %s", fd, arg2);
  // avoid blocking in stdin/stdout/stderr
  if (fd == 0 ||
      ((fd == 1 || fd == 2) && read_mode == 1) ||
      IS_RESERVED_FD(fd)) {
        *arg1 = -1;
      }
  mem_area_ptr[offset].id = id;
  mem_area_ptr[offset].size = read_mode;
  mem_area_ptr[offset].addr = fd;
  mem_area_ptr[offset].ty = FDOPEN;
  mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

// FILE *freopen(const char *path, const char *mode, FILE *stream);

void entry_lseek(uint32_t id, int32_t *arg1) {
    int32_t offset = get_mem_offset();
    int fd = *arg1;
    if (fd == 0 || IS_RESERVED_FD(fd)) *arg1 = -1;
    mem_area_ptr[offset].id = id;
    mem_area_ptr[offset].size = 1;
    mem_area_ptr[offset].addr = fd;
    mem_area_ptr[offset].ty = LSEEK;
    mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

void entry_read(uint32_t id, int32_t *arg1) {
    int32_t offset = get_mem_offset();
    int fd = *arg1;
    if (fd == 0 || fd == 1 || fd == 2 || IS_RESERVED_FD(fd)) *arg1 = -1;
    mem_area_ptr[offset].id = id;
    mem_area_ptr[offset].size = 2;
    mem_area_ptr[offset].addr = fd;
    mem_area_ptr[offset].ty = READ;
    mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

void entry_write(uint32_t id, int32_t *arg1) {
     int32_t offset = get_mem_offset();
    int fd = *arg1;
    if (fd == 0 || IS_RESERVED_FD(fd)) *arg1 = -1;
    mem_area_ptr[offset].id = id;
    mem_area_ptr[offset].size = 1;
    mem_area_ptr[offset].addr = fd;
    mem_area_ptr[offset].ty = WRITE;
    mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

void entry_close(uint32_t id, int32_t *arg1) {
    int32_t offset = get_mem_offset();
    // do not close anything
    int fd = *arg1;
    if (IS_RESERVED_FD(fd)) *arg1 = -1;
    mem_area_ptr[offset].id = id;
    mem_area_ptr[offset].size = 1;
    mem_area_ptr[offset].addr = fd;
    mem_area_ptr[offset].ty = CLOSE;
    mem_area_ptr[offset].stmt_index = *stmt_index_ptr;
}

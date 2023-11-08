#include "../common.h"

/* Input buffer */
void test_load_buf(char *buf, int len);
void test_load_fp(FILE *fp);

/* File input */
// abort
// infer: @[$0] = $read_file
void test_load_file(char *file_name);
// abort
// infer: @[$0] = $read_file
void test_load_file2(char *arg1);
// abort
// infer: @[$0] = $read_file
void test_load_file3(char *arg1);
// abort
// infer: @[$0][name] = $read_file
void test_load_file4(ArrayWrap warp);
// abort
// infer: @[$0] = $read_fd
void test_load_fd(int fd);

typedef struct FdWrap {
  char *name;
  int fd;
} FdWrap;

// abort
// infer: @[$0][fd] = $read_fd
void test_load_fd2(FdWrap wrap);

void test_long_buffer(char *, int);
void test_long_buffer2(ArrayWrap, int);
void test_long_buffer3(ArrayWrap *, int);

void test_dict(char *buf, int len);

char *util_get_buf();
char *util_get_buf2();

// depend: util_get_buf,util_get_buf2
// ignore
void test_buf_splice(int magic, char *buf);

void test_buf_seed(char *buf, int len);

void test_buffer_len_and_non_null(int sw, ArrayWrap *array_list, int n);

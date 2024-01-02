#include "constraint.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

void test_div_zero(int a, int b ) {
  int c = 1023 / b; 
  if (c > 50 && a == 12345) {
    abort();
  }
}

void test_null_ptr(int a, ArrayWrap *b, int c) {
  if (a == 123) {
    if (b != NULL && *(b->name)) {
      if (c == 123456) {
        abort();
      }
    }
  }
}

void test_null_field(ArrayWrap arr) {
  if (strcmp(arr.name, "test") == 0) {
    abort();
  }
}

void test_buffer_len(int sw, int sw2, unsigned char *buffer, int *len) {
  // sw1 to skip the pilot infer
  if (buffer != NULL && len != NULL && sw == 654321) {
    int a = len[0];
    if (a < 16) {
      return;
    }
    printf("len: %d, val: %d\n", a, buffer[(a - 1)]);
    // check sw2 to pass the crash infer
    if (sw2 == 123456) {
      abort();
    }
  }
}

void test_buffer_len_in_struct(ArrayWrap arr) {
  if (arr.name == NULL) return;
  for (int i = 0; i < arr.len; i++) {
    printf("%c\n", arr.name[i]);
  }
}

void test_buffer_combined_len(int sw, int sw2, unsigned char *buffer,
                              unsigned int a, unsigned int b) {
  // sw1 to skip the pilot infer
  if (buffer != NULL && sw == 654321) {
    int n = a * b;
    if (n < 4) return;
    for (int i = 0; i < n; i++) {
      printf("Test %d", buffer[i]);
    }
    if (a == 1 || b == 1) return;
    // check sw2 to pass the crash infer
    if (sw2 == 123456) {
      abort();
    }
  }
}

void test_buffer_len_with_constant(int sw, int sw2, unsigned char *buffer,
                              unsigned int len) {
  if (buffer != NULL && sw == 654321) {
    int n = len * 2;
    if (n < 32) return;
    for (int i = 0; i < n; i++) {
      printf("Test %d", buffer[i]);
    }
    // check sw2 to pass the crash infer
    if (sw2 == 123456) {
      abort();
    }
  }
}

void test_buffer_len_with_pos(int sw, int sw2, unsigned char *buffer,
                              unsigned int n, unsigned int spos,
                              unsigned int epos) {
  // sw1 to skip the pilot infer
  if (buffer != NULL && sw == 654321) {
    if (n < 20 || spos >= n || epos >= n || epos <= spos) return;
    for (int i = spos; i <= epos; i++) {
      printf("Test %d", buffer[i]);
    }
    // check sw2 to pass the crash infer
    if (sw2 == 123456) {
      abort();
    }
  }
}

void test_buffer_len2(int sw, int sw2, ArrayWrap *array) {
  // check sw1 to skip the pilot infer
  if (array != NULL && array->name != NULL && sw == 654321) {
    if (array->len < 20) return;
    if ((array->name[array->len - 1] >= 0)) {
      // check sw2 to pass the crash infer
      if (sw2 == 123456) {
        abort();
      }
    }
  }
}

void test_buffer_len3(char *arg1, unsigned int arg2) {
  if (arg2 < 20) return;
  for (int i = 0; i < arg2; i++) {
    printf("Test %d", arg1[i]);
  }
  if (arg2 > 3) {
    if (arg1[0] == 'a') {
      if (arg1[1] == 'b') {
        if (arg1[2] == 'c') {
          abort();
        }
      }
    }
  }
}


void test_two_buffer_len(char* buf1, char* buf2, int len, int sw) {
  if (buf1 != NULL && buf2 != NULL) {
    if (len < 16) {
      return;
    }
    for (int i = 0; i < len; i++) {
      printf("Test %d %d", buf1[i], buf2[i]);
    }
    if (sw == 12345) {
      abort();
    }
  }
}

void test_two_buffer_len2(char** bufs, int* sizes, int nbufs, int sw) {
  if (bufs != NULL && sizes != NULL) {
    for (int i = 0; i < nbufs; i++) {
      if (bufs[i] == NULL || sizes[i] < 0) {
        return;
      }
      for(int j = 0; j < sizes[i]; j++) {
        printf("Test %d\n", bufs[i][j]);
      }
    }
    if (sw == 12345) {
      abort();
    }
  }
}

void test_buffer_index(char *buf, unsigned int index, int magic) {
  if (index < 20) return;
  int val = buf[index];
  if (val == 0x48 && magic == 12345) {
    abort();
  }
}

void test_buffer_index2(char *buf, unsigned int index, int magic) {
  if (index < 15) return;
  int k = index * 3;
  int val = buf[k];
  if (val == 0x48 && magic == 12345) {
    abort();
  }
}

void test_buffer_index3(char *name, int index) {
  if (name == NULL) return;
  printf("%d\n", name[index]);
}

void test_underflow(int val, int val2, int val3) {
  unsigned int loop = val - 1;
  for (unsigned int i = 0; i < loop; i++) {
      printf("test");
  }
  unsigned int loop2 = val2 - 1;
  for (unsigned int i = 0; i < loop2; i++) {
      printf("test");
  }
  if (val == 1234 && val3 == 7712) {
    abort();
  }
}

void test_oom(unsigned int num) {
  for (int i = 0; i < num; i++) {
    int size = 500000;
    int *ptr = malloc(size);
    printf("ptr: %p\n", ptr);
    if (ptr != NULL) {
      memset(ptr, 0, size);
    }
  }
}

void test_timeout(unsigned int num) {
  if (num > 2000) return;
  sleep(num); 
}

uint32_t test_get_uint_32(char* buf) {
  uint32_t uval =
       ((uint32_t)(*(buf    )) << 24) +
       ((uint32_t)(*(buf + 1)) << 16) +
       ((uint32_t)(*(buf + 2)) <<  8) +
       ((uint32_t)(*(buf + 3))      ) ;

   return uval; 
}

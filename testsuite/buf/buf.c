#include "buf.h"
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void test_load_buf(char *buf, int len) {
  if (len < 20) {
    return;
  }

  uint16_t x = 0;
  int32_t y = 0;
  int32_t z = 0;
  uint32_t a = 0;

  memcpy(&x, buf + 1, 2);   // x 1 - 2
  memcpy(&y, buf + 4, 4);   // y 4 - 7
  memcpy(&z, buf + 10, 4);  // 10 - 13
  memcpy(&a, buf + 14, 4);  // 14 - 17
  printf("x: %d, y:%d, z: %d, a: %d\n", x, y, z, a);
  if (x > 12300 && x < 12350 && z < -100000000 && z > -100000005 &&
      z != -100000003 && y >= 987654321 && y <= 987654325 && a == 123456789) {
    printf("hey, you hit it \n");
    abort();
  }
}

void test_load_fp(FILE *fp) {
  char buf[255];
  if (!fp) {
    printf("st err\n");
    return;
  }
  int len = 20;
  size_t ret = fread(buf, sizeof *buf, len, fp);
  fclose(fp);
  printf("len: %ld\n", ret);
  if (ret < len) {
    printf("input fail \n");
    return;
  }
  test_load_buf(buf, len);
}


void test_load_file(char *file_name) {
  FILE *fp = fopen(file_name, "rb");
  test_load_fp(fp);
}

void test_load_file2(char *arg1) {
  FILE *fp = fopen(arg1, "rb");
  test_load_fp(fp);
}

void test_load_file3(char *arg1) {
  printf("filename: %s\n", arg1);
  int fd = open(arg1, O_RDONLY);
  printf("fd: %d\n", fd);
  if (fd > 0) {
    char buf[50];
    int n = read(fd, buf, 20);
    printf("read %d byte\n", n);
    if (n >= 20) {
      test_load_buf(buf, n);
    }
  }
}

void test_load_file4(ArrayWrap wrap) {
  FILE *fp = fopen(wrap.name, "rb");
  test_load_fp(fp);
}

void test_load_fd(int fd) {
  FILE* fp = fdopen(fd, "rb");
  test_load_fp(fp);
}

void test_load_fd2(FdWrap wrap) {
  FILE* fp = fdopen(wrap.fd, "rb");
  test_load_fp(fp);
}

void test_long_buffer(char *buffer, int a) {
  if (buffer[550]) {
    if (a == 123456) {
      abort();
    }
  }
}

void test_long_buffer2(ArrayWrap a, int b) {
  if (a.name != NULL && a.name[550]) {
    if (b == 123456) {
      abort();
    }
  }
}

void test_long_buffer3(ArrayWrap *a, int b) {
  if (a != NULL && a->name[550]) {
    if (b == 123456) {
      abort();
    }
  }
}

char *util_get_buf() {
  char *buf = malloc(50);
  memset(buf, 0, 50);
  strcpy(buf, "{ password 123456 }");
  return buf;
}

char *util_get_buf2() {
  char *buf = malloc(50);
  memset(buf, 0, 50);
  strcpy(buf, "{ PASSWORD 666123 }");
  return buf;
}

void test_buf_splice(int magic, char *buf) {
  if (buf == NULL) {
    return;
  }
  if (magic != 66666) return;

  char key[100] = "empty";
  int value = 0;
  int ret = sscanf(buf, "{ %s %d }", key, &value);
  printf("key: %s, value: %d, ret: %d\n", key, value, ret);

  if (strncmp(key, "password", 10) == 0) {
    if (value == 66612) {
      abort();
    }
  }
  printf("key: %s, value: %d, ret: %d\n", key, value, ret);
  if (strncmp(key, "PASSWORD", 10) == 0) {
    if (value == 123456) {
      abort();
    }
  }
}

void test_buf_seed(char *buf, int len) {
  if (buf != NULL && len >= 9) {
    int val = atoi(buf);
    printf("buf: %s, val: %d\n", buf, val);
    if (val == 12345678) {
      abort();
    }
  }
}

void test_buffer_len_and_non_null(int sw, ArrayWrap *array_list, int n) {
  if (n < 10) return;
  for (int i = 0; i < 10; i++) {
     ArrayWrap a = array_list[i];
     for (int j = 0; j < a.len; j++) {
        printf("%c\n", a.name[j]);
     }
  }
  if (sw == 123456) {
      abort();
  }
}

void test_dict(char *buf, int len) {
  if (len < 12) {
    return;
  }
  printf("last: %d\n", buf[len - 1]);
  if (buf[0] != 'h') {
    return;
  }
  for (int i = 0; i < 6; i++) {
    buf[i] = toupper(buf[0]);
  }
  if (strcmp(buf, "HOPPER") != 0) {
    printf("hopper\n");
    if ((buf[6] - buf[7] == 0) && buf[6] == 0x66) {
      printf("66 \n");
      if (buf[8] - buf[9] + buf[10] - buf[11] == 2) {
        abort();
      }
    }
  }
}
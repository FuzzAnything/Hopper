#include "strcmp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void test_strcmp(char *s) {
  printf("addr: %p\n", s);
  if (s != NULL && strcmp(s, "test") == 0) {
    abort();
  }
}

void test_strncmp(char *s) {
  printf("addr: %p\n", s);
  if (s != NULL && strncmp(s, "test445566", 10) == 0) {
    abort();
  }
}

static char *TEST_STR = "test112233";

void test_strcmp2(char *s) {
  printf("addr1: %p, addr2: %p\n", s, TEST_STR);
  if (s != NULL && strcmp(s, TEST_STR) == 0) {
    abort();
  }
}

void test_strcmp_indirect(char *s) {
  printf("addr: %p\n", s);
  if (s != NULL && strlen(s) >= 8) {
    printf("s: %d %d %d %d\n", s[4], s[5], s[6], s[7]);
    char buf[10];
    strncpy(buf, &s[4], 4);
    buf[4] = 0;
    printf("buf: %p: %d %d %d %d\n", buf, buf[0], buf[1], buf[2], buf[3]);
    if (s != NULL && strcmp(buf, "test") == 0) {
      abort();
    }
  }
}

void test_strcmp_in_struct(TestCustom *b) {
  if (b != NULL && b->book_id == 20000) {
    if (b->cat_id > 12345 && b->cat_id < 22222) {
      if (strcmp(b->title, "test") == 0) {
        printf("boom at targetp! id: %d, cat: %d\n", b->book_id, b->cat_id);
        abort();
      }
    }
  }
}

uint32_t TRST_ARR[] = {1, 2, 3, 4, 5, 6, 7, 8};
void test_memcmp(uint32_t *s, int n) {
  if (n > 8) n = 8;
  if (s != NULL && n > 0 && memcmp(s, TRST_ARR, n * 4) == 0) {
    abort();
  }
}

#define VERSION "1.6.37"
void test_match_version(char* ver) {
   int match = 1;
   int i = -1;
   if (ver != 0)
   {
      int found_dots = 0;

      do
      {
         i++;
         printf("%d vs %d \n", ver[i], VERSION[i]);
         if (ver[i] != VERSION[i]) {
            // printf("bingo\n");
            match = 0;
         }
         if (ver[i] == '.') {
            found_dots++;
         }
      } while (found_dots < 2 && ver[i] != 0 &&
            VERSION[i] != 0);
   } else {
    match = 0;
   }

  if (match != 0) {
    abort();
  }
}

#include "basic.h"

#include <ctype.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void test_cmp_var(int a, long b, char c) {
  printf("a: %d, b:%ld, c:%d\n", a, b, c);
  if (a == 20000) {
    if (b > 1000000 && b < 1000080) {
      if (c == 0xa) {
        abort();
      }
    }
  }
}

void test_cmp_struct(struct CmpStruct p) {
  if (p.x == 123345) {
    if (p.y == 45677) {
      abort();
    }
  }
}

void test_switch(int a, int b) {
  switch (a) {
    case 12312213:
      printf("11\n");
      break;
    case -1111:
      printf("3\n");
      break;
    case 3330000:
      printf("4\n");
      if (b == 77881) {
        abort();
      }
      break;
    case 5888:
      printf("5\n");
      break;
    case -897978:
      printf("6\n");
      break;
    default:
      break;
  }
}

void test_switch2(int a) {
  switch (a) {
    case 1:
      printf("11");
      break;
    case 2:
      printf("22");
      break;
    case 3:
      printf("3");
      break;
    case 4:
      printf("4");
      break;
    case 5:
      printf("5");
      break;
    case 6:
      printf("6");
      break;
    case 7:
      printf("6");
      break;
    case 8:
      printf("6");
      break;
    case 9:
      printf("6");
      break;
    case 10:
      printf("6");
      break;
    case 9999:
      printf("6");
      break;
    case 10000:
      printf("6");
      abort();
      break;
    case 10001:
      printf("6");
      break;
    default:
      printf("123");
      break;
  }
}

void test_cmp_float(float a, float b) {
  // ucomiss
  if (a == 1.2) {
    printf("hey, you hit it2 \n");
  }
  if (b == 2.1f) {
    printf("hey, you hit it \n");
    abort();
  }
}

int gval = 0;

void util_set_gval() { gval = 1; }

void test_use_gval(int num) {
  if (gval > 0 && num == 12345) {
    abort();
  }
}

char *util_static_ret() { return "test"; }

void test_enum(enum TestEnum v1, enum TestEnum v2) {
  if (v1 == Tue) {
    if (v2 == Sun) {
      abort();
    }
  }
}

void test_union(TestUnion2 a) {
  if (a.member1 != NULL) {
    if (a.member1->cat_id == 444444) {
      abort();
    }
  }
}

void test_complicated_struct(ComplicatedStruct *a) {
  if (a != NULL) {
    if (a->ty == 2) {
      if (a->inner_union.member2.id == 11111) {
        if (a->inner_union2 != NULL) {
          abort();
        }
      }
    }
  }
}

void test_complicated_struct2(ComplicatedStruct *a) {
  if (a != NULL) {
    if (a->ty == 3) {
      if (a->inner_union.member3 != NULL) {
        if (a->inner_union.member3->val == 222222) {
          abort();
        }
      }
    }
    if (a->ty == 1) {
      if (a->inner_union.member1 != NULL) {
        if (a->inner_union.member1->cat_id == 3333333) {
          abort();
        }
      }
    }
    if (a->ty == 6) {
      if (a->inner_union.member6 != NULL) {
        if (a->inner_union.member6->len == 3333333) {
          abort();
        }
      }
    }
  }
}

int util_variadic_function1(int a, ...) { return 0; }

int util_variadic_function2(int a, ...) { return 0; }

int util_variadic_function3(int a, ...) { return 0; }

void util_long_args_function(int a, int b, int c, int d, char e, char f, char g,
                             char h, long i, long j, long k, long l, long m) {}

void test_variadic_function_ptr(int (*f)(int, ...), int b) {
  if (f == util_variadic_function3 && b == 100000) {
    abort();
  }
}

void test_long_args_one_level(LONG_FN_PTR a, int b) {
  if (a == NULL && b == 100000) {
    abort();
  }
}

void test_long_args_two_level(LONG_FN_PTR *a, int b) {
  if (a) {
    if (*a == NULL && b == 100000) {
      abort();
    }
  }
}

void test_private_field(ValWithPrivateField obj) {
  if (obj.val == 0x12345) {
    abort();
  }
}

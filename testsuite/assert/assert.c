#include <stdlib.h>
#include <stdio.h>

int test_assert_eq(int magic) {
   if (magic == 23334) {
      return 1;
   }
   return 0;
}

int test_assert_neq(int magic) {
   if (magic == 23334) {
      return 1;
   }
   return 0;
}
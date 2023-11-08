/*
    Testing for string comparison
*/
#include <stdio.h>
typedef unsigned int uint32_t;
typedef struct TestCustom {
  char title[10];
  int book_id;
  int cat_id;
  float price;
} TestCustom;


void test_strcmp(char *s);
void test_strcmp2(char *s);
void test_strncmp(char *s);
void test_strcmp_indirect(char *s);
void test_strcmp_in_struct(TestCustom *b);

/* compare in a loop */
void test_match_version(char* ver);

/* Mem Related */
void test_memcmp(uint32_t *s, int n);

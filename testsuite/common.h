#include <stdio.h>

/* Types and Structs */
typedef unsigned int uint32_t;
typedef void (*LONG_FN_PTR)(int, int, int, int, char, char, char, char, long,
                            long, long, long, long);
typedef void *HANDLE;

typedef struct TestCustom {
  char title[10];
  int book_id;
  int cat_id;
  float price;
} TestCustom;

typedef struct CmpStruct {
  int x;
  int y;
} CmpStruct;

typedef struct TestCustom2 {
  int id;
  char content[10];
} TestCustom2;

typedef struct ArrayWrap {
  char *name;
  int len;
} ArrayWrap;

typedef struct ListNode {
  int val;
  struct ListNode *next;
  struct ListNode *next2;
  struct ListNode *next3;
} ListNode;

typedef struct ListNodeWrapper {
  ListNode *inner;
} ListNodeWrapper;

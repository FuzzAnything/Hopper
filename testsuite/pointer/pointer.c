#include "pointer.h"

#include <stdlib.h>
#include <string.h>

struct OpaqueType *util_create_opaque() {
  void *ptr = malloc(sizeof(ArrayWrap));
  ArrayWrap *arr = (ArrayWrap *)ptr;
  arr->name = NULL;
  arr->len = 0;
  return ptr;
}

void util_opaque_init(struct OpaqueType *ptr) {
  if (ptr != NULL) {
    ArrayWrap *arr = (ArrayWrap *)ptr;
    arr->name = malloc(10);
    strcpy(arr->name, "test");
    arr->name[4] = 0;
    arr->len = 4;
  }
}

void test_opaque_arg(struct OpaqueType *ptr, int magic) {
  if (ptr == NULL) exit(0);
  ArrayWrap *arr = (ArrayWrap *)ptr;
  if (magic == 1234 && arr->name != NULL) {
    char name[20];
    strcpy(name, arr->name);
    name[arr->len] = 0;
    printf("name: %s\n", name);
    if (strcmp(name, "test") == 0) {
      abort();
    }
  }
}

void test_opaque_arg2(struct OpaqueType *ptr) {
  if (ptr == NULL) abort();
}

HANDLE util_handle() {
  int *ptr = malloc(sizeof(int));
  *ptr = 12345;
  return ptr;
}

void test_handle(HANDLE handle, int magic) {
  if (handle != NULL) {
    int *val = (int *)handle;
    if (*val == 12345 && magic == 789111) {
      abort();
    }
  }
}

void test_handle_wrap(HandleWrap handle, int magic) {
  test_handle(handle.handle, magic);
}

struct Full {
  struct Partial x;
  int *b;
  char *c;
};

SemiOpaque *util_get_partial_pointer() {
  struct Full *ret = (struct Full *)malloc(sizeof(struct Full));
  int *b = (int *)malloc(sizeof(int));
  *b = 123456;
  ret->x.a = 0;
  ret->b = b;
  ret->c = "test";
  return (SemiOpaque *)ret;
}

void test_partial_pointer(SemiOpaque *ptr, int magic) {
  struct Full *full = (struct Full *)ptr;
  if (strcmp(full->c, "test") == 0 && *(full->b) == 123456 && magic == 6666) {
    abort();
  }
}

void util_init_opaque_type(struct OpaqueType **a) {
  ArrayWrap *arr = (ArrayWrap *)malloc(sizeof(ArrayWrap));
  arr->name = "test";
  arr->len = 4;
  *a = (struct OpaqueType *)arr;
}

void test_init_opaque(OpaqueWrapper *ptr, int b) {
  if (ptr == NULL) exit(0);
  ArrayWrap *arr = (ArrayWrap *)ptr->opaque;
  if (arr->len == 4 && strcmp(arr->name, "test") == 0) {
    if (b == 123456) {
      abort();
    }
  }
}

void util_fn_pointer(void (*f)(TestCustom *p), TestCustom *p) {
  if (f != NULL) (*f)(p);
}

void test_function_pointer_ret(int a, TestCustom (*f)(int, int)) {
  TestCustom ret = f(0, 1);
  if (ret.price == 0) {
    if (a == 123456) {
      abort();
    }
  }
}

void test_multi_func_pointer(TestCustom (*f)(int, int),
                             TestCustom (*f2)(int, int),
                             TestCustom (*f3)(int)) {
  TestCustom r1 = f(1, 1);
  TestCustom r2 = f2(1, 1);
  TestCustom r3 = f3(1);
  if (r1.title[0] == '\0' && r2.cat_id == 0 && r3.cat_id == 0) {
    abort();
  }
}

ListNode *util_reference_circle() {
  ListNode *first = (ListNode *)malloc(sizeof(ListNode));
  first->val = 1;
  first->next = NULL;
  // first->next2 = NULL;
  // first->next3 = NULL;
  ListNode *second = (ListNode *)malloc(sizeof(ListNode));
  second->val = 2;
  second->next = first;
  // second->next2 = NULL;
  // second->next3 = NULL;
  first->next = second;
  printf("%p", first);
  return first;
}

void test_visit_list_node(ListNode *curr) {
  if (curr != NULL) {
    printf("next %p\n", curr->next);
    test_visit_list_node(curr->next);
  }
}

void test_visit_list_node2(ListNode **curr, int size) {
  if (curr != NULL) {
    int i = 0;
    while (i < size) {
      test_visit_list_node(curr[i]);
      i++;
    }
  }
}

void test_visit_list_node3(ListNodeWrapper *a) {
  if (a != NULL) {
    test_visit_list_node(a->inner);
  }
}

TestCustom2 *util_create_TestCustom2() {
  return (TestCustom2 *)malloc(sizeof(TestCustom2));
}

char *util_get_content(TestCustom2 *a) {
  if (a != NULL) {
    return a->content;
  }
  return NULL;
}

void test_illegal_free(char *a) { free(a); }

void test_indirect_free_ptr(PtrFnWarp *f_wrap) {
  if (f_wrap != NULL && f_wrap->f != NULL) {
    (*f_wrap->f)(NULL);
    if (f_wrap->f == free) {
      abort();
    }
  }
}

void util_set_free_fn(PtrFnWarp *f_wrap) {
  f_wrap->f = free;
}

TestCustom *util_create_pointer(char *title, int n) {
  TestCustom *book = malloc(sizeof(TestCustom));
  book->book_id = 20000;
  book->cat_id = n;
  book->price = 0.5;
  if (title != NULL) {
    strncpy(book->title, title, 10);
    book->title[9] = 0;
  }
  return book;
}

void util_free_pointer(TestCustom *b) {
  if (b != NULL) free(b);
}

void test_with_update(TestCustom *b) {
  if (b != NULL) {
    int mul = b->book_id * b->price;
    printf("mul %d\n", mul);
    if (mul == 10000) {
      printf("aaa\n");
    }
    if (mul == 10001) {
      if (strcmp(b->title, "test123") == 0) {
        abort();
      }
    }
  }
}

void test_custom_cast(void *p) {
  printf("ptr %p\n", p);
  if (p != NULL) {
    int *pi = p;
    if (*pi == 12345) {
      abort();
    }
  }
}

void test_custom_cast2(int magic, void *arg) {
  if (magic != 12345 || arg == NULL) {
    return;
  }
  ListNode *node = (ListNode *)arg;
  if (node->val != 55566) {
    return;
  }
  ListNode *next = node->next;
  printf("ptr: %p\n", next);

  if (next != NULL) {
    int *val_ptr = &next->val;
    printf("ptr2: %p\n", val_ptr);
    if (*val_ptr == 77788) {
      abort();
    }
  }
}

void test_infer_cast(void *p) {
  printf("ptr %p\n", p);
  if (p != NULL) {
    char p1 = ((char*)p)[0];
    char p2 = ((char*)p)[1];
    if (p1 ==0x12 && p2 != 0 && p2 == 0x34) {
      abort();
    }
  }
}

void test_infer_cast2(void **p) {
  printf("ptr %p\n", p);
  if (p != NULL && *p != NULL) {
    char p1 = ((char*)*p)[0];
    char p2 = ((char*)*p)[1];
    if (p1 ==0x12 && p2 != 0 && p2 == 0x34) {
      abort();
    }
  }
}

void test_infer_cast3(PtrWrap p) {
  if (p.ptr != NULL) {
    char p1 = ((char*)p.ptr)[0];
    char p2 = ((char*)p.ptr)[1];
    if (p1 ==0x12 && p2 != 0 && p2 == 0x34) {
      abort();
    }
  }
}
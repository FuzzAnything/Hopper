/*
  Testing for pointers
*/

#include "../common.h"

/* Test opaque pointer */
struct OpaqueType;
struct OpaqueType *util_create_opaque();
void util_opaque_init(struct OpaqueType *ptr);
// depend: util_create_opaque,util_opaque_init
void test_opaque_arg(struct OpaqueType *ptr, int magic);

// depend: util_create_opaque
// infer: @[$0] = $need_init
void test_opaque_arg2(struct OpaqueType *ptr);

/* Test for type alias for opaque pointer */
typedef struct HandleWrap {
  HANDLE handle;
} HandleWrap;
HANDLE util_handle();
// depend: util_handle
void test_handle(HANDLE handle, int magic);
// depend: util_handle
void test_handle_wrap(HandleWrap handle, int magic);

/* Test opeauqe that partial exported */
struct Partial {
  int a;
};

typedef struct Partial SemiOpaque;

SemiOpaque *util_get_partial_pointer();
// depend: util_get_partial_pointer
// abort
// infer: Partial = $opaque
void test_partial_pointer(SemiOpaque *ptr, int magic);

/* Test opaque type with warpper */
typedef struct OpaqueWrapper {
  struct OpaqueType *opaque;
} OpaqueWrapper;

void util_init_opaque_type(struct OpaqueType **);
// depend: util_init_opaque_type
void test_init_opaque(OpaqueWrapper *, int);

/* Test function pointers */
void util_fn_pointer(void (*f)(TestCustom *p), TestCustom *p);

// depend: GENERATED_hopper_callback_*
void test_function_pointer_ret(int a, TestCustom (*)(int, int));

// depend: GENERATED_hopper_callback_*
void test_multi_func_pointer(TestCustom (*)(int, int), TestCustom (*)(int, int), TestCustom (*)(int));

/* Test pointers that makes a reference circle */

ListNode *util_reference_circle();
// depend: util_reference_circle
// ignore
void test_visit_list_node(ListNode *);
// depend: util_reference_circle
// ignore
void test_visit_list_node2(ListNode **, int);
// depend: util_reference_circle
// ignore
void test_visit_list_node3(ListNodeWrapper *);

/* Test checking for pointer frees */
TestCustom2 *util_create_TestCustom2();
char *util_get_content(TestCustom2 *);
// depend: util_get_content,util_create_TestCustom2
// ignore
void test_illegal_free(char *);

typedef struct PtrFnWarp {
  void (*f)(void *f);
} PtrFnWarp;
void util_indirect_free_ptr(PtrFnWarp f_wrap);
PtrFnWarp util_get_free_fn();

/* Explicitly Related calls */
TestCustom *util_create_pointer(char *title, int n);
void util_free_pointer(TestCustom *b);
// depend: util_create_pointer
void test_with_update(TestCustom *b);

/* Type Casting */
void test_custom_cast(void *p);
// void is cast to a type that contains pointer
void test_custom_cast2(int magic, void* arg);

// abort
// infer: @[$0] = $cast_from(*mut i8)
void test_infer_cast(void *p);

// abort
// infer: @[$0][&.$0] = $cast_from(*mut i8)
void test_infer_cast2(void **p);

typedef struct PtrWrap {
  void* ptr;
} PtrWrap;

// abort
// infer: @[$0][ptr] = $cast_from(*mut i8)
void test_infer_cast3(PtrWrap p);
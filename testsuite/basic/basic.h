/*
  Basic testing for C APIs
*/

#include "../common.h"

/* Test value compare */
void test_cmp_var(int a, long b, char c);
void test_cmp_struct(struct CmpStruct p);
void test_switch(int a, int b);
void test_switch2(int a);
// ignore
// float compare is not support now, it use ucomiss instruction
void test_cmp_float(float a, float b);

/* Implicitly Related calls */
void util_set_gval();
// depend: util_set_gval
void test_use_gval(int num);

/* utils */
char *util_static_ret();

/* Test for complicated strctures */
enum TestEnum {
  Mon,
  Tue,
  Wed,
  Thu,
  Fri,
  Sut,
  Sun,
};

typedef union TestUnion {
  int i;
  float f;
  char str[20];
} TestUnion;


typedef union TestUnion2 {
  int num;
  TestCustom *member1;
  int num2;
} TestUnion2;

typedef struct ComplicatedStruct {
  int ty;
  union {
    int num;
    TestCustom *member1;
    TestCustom2 member2;
    ListNode *member3;
    ListNodeWrapper *member4;
    ListNode *member5;
    ArrayWrap *member6;
  } inner_union;
  TestUnion2 *inner_union2;
} ComplicatedStruct;
void test_enum(enum TestEnum v1, enum TestEnum v2);
void test_union(TestUnion2);
void test_complicated_struct(ComplicatedStruct *);
void test_complicated_struct2(ComplicatedStruct *);

/* Test private fields for structure */
typedef struct ValWithPrivateField {
  int val;
  int __unused[16];
} ValWithPrivateField;

void test_private_field(ValWithPrivateField obj);

/*  Test long and variadic arguments and function pointer */
void util_long_args_function(int, int, int, int, char, char, char, char, long,
                             long, long, long, long);
int util_variadic_function1(int, ...);
int util_variadic_function2(int, ...);
int util_variadic_function3(int, ...);
void test_long_args_one_level(LONG_FN_PTR, int);
void test_long_args_two_level(LONG_FN_PTR *, int);
// ignore
void test_variadic_function_ptr(int (*)(int, ...), int);


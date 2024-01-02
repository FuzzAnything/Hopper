/*
    Test for constraint inference
*/
#include "../common.h"

// abort
// infer: @[$1] = $non_zero 
void test_div_zero(int a, int b );

// abort
// infer: @[$1][&.$0.name] = $non_null
void test_null_ptr(int, ArrayWrap *, int);

// abort
// infer: @[$0][name] = $non_null
void test_null_field(ArrayWrap arr);

// abort
// infer: @[$3][&.$0] = $len($2)
void test_buffer_len(int, int, unsigned char*, int*);

// infer: @[$0][len] = $len([$0][name])
void test_buffer_len_in_struct(ArrayWrap arr);

// abort
// infer: @[$2] = $len_factors($3, $4)
void test_buffer_combined_len(int sw, int sw2, unsigned char *buffer, unsigned int a, unsigned int b);

// abort
// infer: @[$2] = $len_factors(2, $3)
void test_buffer_len_with_constant(int sw, int sw2, unsigned char *buffer, unsigned int len);

// abort
void test_buffer_len_with_pos(int sw, int sw2, unsigned char *buffer,
                              unsigned int n, unsigned int spos, unsigned int epos) ;

// abort
// infer: @[$2][&.$0.len] = $len([$2][&.$0.name])
void test_buffer_len2(int, int, ArrayWrap*);

// abort
// infer: @[$1] = $len($0)
void test_buffer_len3(char *arg1, unsigned int arg2);

// abort
// infer: @[$2] = $len($0); @[$1] = $arr_len($len($0))
void test_two_buffer_len(char* buf1, char* buf2, int len, int sw);

// abort
// infer: @[$2] = $len($0); @[$1][&.$0] = $len([$0][&.$0])
// @[$1] = $arr_len($len($0)); 
void test_two_buffer_len2(char** bufs, int* sizes, int nbufs, int sw);

// abort
// infer: @[$1] = $range(0, $len($0))
void test_buffer_index(char *buf, unsigned int index, int magic);

// abort
// infer: @[$0] = $len_factors(3, 0..$len($1))
void test_buffer_index2(char *buf, unsigned int index, int magic);

// infer: @[$1] = $range(0, $len(0))
void test_buffer_index3(char *name, int index);

// abort
// infer: @[$0] = $range(1, 4096); @[$1] = $range(1, 4096)
void test_underflow(int val, int val2, int val3);

// infer: @[$0] = $range(0, 4096);
void test_oom(unsigned int num);

// ignore 
// infer: @[$0] = $range(0, 4096);
void test_timeout(unsigned int num);

// infer: @[$0][&] = $arr_len(4)
uint32_t test_get_uint_32(char* buf);
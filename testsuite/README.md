# Testsuite for Hopper

Testsuite includes some simple functions that wrote by developers artificially for testing.

## Build and run testsuite

- build and run all tests
```
./test.sh build_all
./test.sh test_all
```

- build and run specific test case
```sh
# build library under `basic` directory
./test.sh build basic
# test specific function under `basic`` directory
./test.sh test basic test_cmp_var
```

If test success (find any crash in N rounds, N is defined in test.sh), the script will print `test success`.
otherwise, it will print `test fail`.

## How to write testcase

If you want to define a new library, you should create a directory (e.g. test), and it should has following files:
- test.c
- test.h
- custom.rule


If you just want to add test case in an exsited library. 
- Define the *Entry* function by adding a function whose name is starts with `test_`. The *Entry* function could be *crash* by specific inputs.
- Define the *TOOL* function if needed by adding a function whose name is starts with `util_`. The *Tool* functions is used for providing or mutating arguments for *Entry* functions. 
- Define the dependencies between functions. Just add a comment starts with `// depend: ` in the header file.

```c
void util_set_gval();
// depend: util_set_gval
void test_use_gval(int num);
```

- If you want to ignore a `test_*` function in `test` command. Just add a comment with *ignore* above its declaration.
```c
// ignore
void test_variadic_function_ptr(void (*)(int, ...), int);
```

- If you want to test whether the tool can infer some constraints succesfully or not, e.g. the first argument should be non-null and the second argument is the length of first one, you can define the constraints should be infered by following way.
```c
// infer: @[$0] = $non_null; @[$1] = $len($0)
void test_buf(char* ptr, int len);
```

- If the API function is expected to crash with *abort* signal, you can add `abort` for add checkings. `abort` is checked  in default.
```c
// abort
void test_sth(int maigic);
```

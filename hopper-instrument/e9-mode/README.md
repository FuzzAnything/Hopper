
## E9Patch
- *E9* mode is using [e9pacth](https://github.com/GJDuck/e9patch) for instrumentation. You can read its [paper](https://comp.nus.edu.sg/~gregory/papers/e9patch.pdf) and [documentations](https://github.com/GJDuck/e9patch/tree/master/doc).


## Our plugins
- `hopper-e9-plugin.cpp`: from [E9AFL](https://github.com/GJDuck/e9afl) for branch coverage collection.
- `hopper-instr-plugin.cpp`: our plugin for tracing cmp instructions.

## Test e9 plugin

- Print intermidiate content with JSON format.
```
/root/hopper/install/e9tool  --format='json' -o /root/hopper/testsuite/ctest/libctest_instr.so -M 'plugin("/root/hopper/install/hopper-instr-plugin.so").match()' -P 'plugin("/root/hopper/install/hopper-instr-plugin.so").patch()' -- /root/hopper/testsuite/ctest/libctest.so
```

- Run pacth manually.
```
E9AFL_PATH=/root/hopper/install /root/hopper/install/e9tool -o /root/hopper/testsuite/ctest/output/libctest_cov.so -M 'plugin("/root/hopper/install/hopper-e9-plugin.so").match()' -P 'plugin("/root/hopper/install/hopper-e9-plugin.so").patch()'  -M 'plugin("/root/hopper/install/hopper-instr-plugin.so").match()' -P 'plugin("/root/hopper/install/hopper-instr-plugin.so").patch()'  -- /root/hopper/testsuite/ctest/libctest.so
```

## LLVM Mode
- LLVM mode is still under development. Though it works currently, some features are not yet implemented.
- our `llvm-mode` instrumentation needs llvm dependencies (>= LLVM 10.0) and only tested in LLVM 10.0 and LLVM 14.0 currently.

## Plan
- [x] API-sensitive branch counting
- [x] Cmp hooking
- [x] Resource related hooking

## How to use

- Compile your libraries with `hopper-clang`.
```
CC=hopper-clang
CXX=hopper-clang++
```

- Use hopper to compile the libraries. Hopper can identify the libraries are compiled by the `hopper-clang` and uses the `llvm-mode` automatically.
```
hopper compile --header ./cJSON.h --library ./libcjson.so --output output
```
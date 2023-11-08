# Use Hopper in Windows
ATTN: The Windows feature is no longer being maintained.
ATTN: Hopper was tested in Windows10 **19044.1645**, and **fork() will fail after 19044.1646**.

Since e9patch can only works on Linux environment, Hopper should need both linux and Windows environment.
Hopper uses e9patch to instrument libraries in Linux, and then copy the patched library to Windows environment.

## On Linux side
- Build hopper
```
./build.sh
``` 

- Compile libraries
```
./hopper --header ./cJSON.h --library ./libcjson.dll
```

## On windows side
- Build hopper (toolchain: stable-x86_64-pc-windows-gnu)
```
cargo build --release
```

- Compile libraries
```sh
# ./libcjson.dll is copied from linux side
/path-to-release/hopper-compiler.exe --header ./cJSON.h --library ./libcjson.dll --output output
```

## Fuzz library with Hopper
```sh
./path-to-output/bin/hopper-fuzzer.exe
```

### Envionment variables
- `HOPPER_TASK`: task name. default: `libname_fuzz`.
- `HOPPER_E9_BLACK_LIST`: functions should not be patched. e.g `export HOPPER_E9_BLACK_LIST=xx`
- `HOPPER_USE_THREAD`: `0` use `fork_loop`, `1` use `thread_loop`.
- `HOPPER_USE_THREAD_NUM`: Child process will exit after executing `HOPPER_USE_THREAD_NUM` threads. The higher the number, the faster the speed and the worse the stability. default: `100`.


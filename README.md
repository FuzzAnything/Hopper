# Hopper

Hopper is an tool for generating fuzzing test cases for libraries automatically using **interpretative fuzzing**. It transforms the problem of library fuzzing into the problem of interpreter fuzzing, enabling exploration of a vast range of API usages for library fuzzing out of the box.
Some key features of Hopper include:
- Interpretative API invoking without any fuzz driver. 
- Type-aware mutation for arguments.
- Automatic intra- and inter-API constraints leanring.
- Binary instrumentation support.

To learn more about Hopper, check out our [paper](https://arxiv.org/pdf/2309.03496) at CCS '23.

## Build Hopper
### Build Requirements
- Linux-amd64 (Tested on Ubuntu 20.04 and Debian Buster)
- Rust stable (>= 1.60), can be obtained using [rustup](https://rustup.rs/)
- Clang (>= 5.0, [Install Clang](https://rust-lang.github.io/rust-bindgen/requirements.html)), [rust-bindgen](https://rust-lang.github.io/rust-bindgen/) leverages libclang to preprocess, parse, and type check C and C++ header files.

### Build Hopper itself
```sh
./build.sh
```

The script will create a `install` directory in hopper's root directory, then you can use `hopper`.
To use the command anywhere, you can set the project directory in your PATH variable.

### Using Docker
You can choose to use the Dockerfile, which build the requirements and Hopper.
```
docker build -t hopper ./
docker run --name hopper_dev --privileged -v /path-to-lib:/fuzz -it --rm hopper /bin/bash
```

## Compile library with Hopper
Take `csjon` for example ([More examples](./examples/)).
```sh
hopper compile --header ./cJSON.h --library ./libcjson.so --output output
```

Use `hopper compile --help` to see detailed usage. If the compiling reports errors about header file, refer to the usage of [rust-bindgen](https://rust-lang.github.io/rust-bindgen/), which we used for parsing header file.
You may wrap the header file with the missing definitions.
Hopper uses [E9Patch](https://github.com/GJDuck/e9patch) to instrument binaries by default. Optionally, you can use [LLVM](./hopper-instrument/llvm-mode/) for source code instrumentation.

After running `compile`, you will find that it generates the following files in the output directory:
- `bin/hopper-fuzzer`:  generates inputs, maintatins states, and use `harness` to excuted the inputs.
- `bin/hopper-harness`:  executes the inputs.
- `bin/hopper-translate`:  translates inputs to C source code.
- `bin/hopper-generator`: replays the generate process.
- `bin/hopper-sanitizer`: sanitize and minimize crashes.

#### Header files
- If there are multiple header files, you can crate a new header file, and *include* all of them.
- If header files are compiled depending on specific envoironment variables. You can set it by : `BINDGEN_EXTRA_CLANG_ARGS`.
- If the header file includes API functions that you do not want to test, use `--func-pattern` to filter them while running the fuzzer.

#### Environment variable for compiling
- `HOPPER_MAP_SIZE_POW2`: controls the size of coverage path. The defult value is 16, and it should be in the range of [16, 20]. e.g. `HOPPER_MAP_SIZE_POW2=18`.
- `HOPPER_INST_RATIO`: controls how likely a block will be chosen for instrumentation. The default value is 100, and it should be in the range of (0, 100]. e.g. `HOPPER_INST_RATIO=75`.
- `HOPPER_INCLUDE_SEARCH_PATH`: includes the search path of file in header files. e.g. `HOPPER_INCLUDE_SEARCH_PATH=../`.
- `HOPPER_FUNC_BLACKLIST`: includes function blacklists that hopper won't compile. `bindgen` will not generate code for the functions. e.g. `HOPPER_FUNC_BLACKLIST=f1,f2`.
- `HOPPER_TYPE_BLACKLIST`: includes type blacklists that hopper won't compile. `bindgen` will not generate code for the types. e.g. `HOPPER_TYPE_BLACKLIST=type1,type2`.
- `HOPPER_ITEM_BLACKLIST`: includes item(constants/variables) blacklists that hopper won't compile. `bindgen` will not generate code for the items. e.g. `HOPPER_ITEM_BLACKLIST=IPPORT_RESERVED`
- `HOPPER_CUSTOM_OPAQUE_LIST`: includes custom opaque types we defined. e.g. `HOPPER_CUSTOM_OPAQUE_LIST=type1`.

#### Tips
- You can set the arguments and environment variables for compiling and running in a configuration file named `hopper.config`, see `examples/*` for details.

- Reduce density: If density is larger than 20%, the IDs of edges is likely to have hash-collisions. We can a) increase  `HOPPER_MAP_SIZE_POW2` or b) reduce `HOPPER_INST_RATIO`.

- Multiple libraries: (1) merge the archives into one shared library, e.g. `gcc -shared -o c.so -Wl,--whole-archive a.a b.a -Wl,--no-whole-archive`; (2) pass all of them into hopper compiler by `--library a.so b.so`.

## Fuzz Library with Hopper

```
hopper fuzz output --func-pattern cJSON_*
```

Use `hopper fuzz output --help` to see detailed usage.

After running `fuzz`, it will generate following directories.
- `queue`: generated normal inputs.
- `hangs`: generated timeout inputs.
- `crashes`: generated crash inputs.
- `misc`: store some temporal files or stats.

#### Environment variable for running
- `DISABLE_CALL_DET`: disables call's deterministic mutating.
- `DISABLE_GEN_FAIL`: disables generating programs for functions that have been failed to invoke.
- `HOPPER_SEED_DIR`: provides seeds for byte-like arguments (default: output/seeds if t exists).
- `HOPPER_DICT`: provides dictionary for byte-like arguments. The grammar is the same as AFL's.
- `HOPPER_API_INSENSITIVE_COV`: disables API-sensitive branch counting.
- `HOPPER_FAST_EXECUTE_LOOP`:  number of programs excuted (in a loop) for each fork, set as 0 or 1 to break the loop. e.g. `HOPPER_FAST_EXECUTE_LOOP=10`.

#### System configuration
Set system core dumps as AFL (on the host if you execute Hopper in a Docker container).
```
echo core | sudo tee /proc/sys/kernel/core_pattern
```

### Function pattern 
Hopper generates inputs for all functions that appear in both headers and libiries by default. However, there are two ways to filter functions in Hopper: exlucding functions or including functions. This way, it can be focus on intersting functions.

#### `--func-pattern`
```
hopper fuzz output --func-pattern @cJSON_parse,!cJSON_InitHook,cJSON_*
```
  - The pattern can be a function name, e.g. `cJSON_parse`, or a simple pattern, e.g. `cJSON_*`. 
  - If you have multiple patterns, use `,` to join them, e.g `cJSON_*,HTTP_*`. 
  - You can use `@` prefix to limit the fuzzer to only fuzz specific function, while the others can be candidates that provding values for fields or arguments, e.g. `@cJSON_parse,cJSON_*`.
  - `!` is used as prefix for excluding some specific functions, e.g `!cJSON_InitHook,cJSON_*`.

#### `--custom-rules`
The patterns can be defined in the file passed by `--custom-rules`.

```rust
// hopper fuzz output --custom-rules path-to-file
func_target cJSON_parse
func_exclude cJSON_InitHook
func_include cJSON_*,HTTP_*
```

### Constraints
Hopper infers both intra- and inter-API constraints to invoking the APIs correctlly.  
The constraints are written in `output/misc/constraint.config`. You can remove the file to reset the constraints.
Addtionally, users can defined a file that describe custom constraints for API invocations, which passed by `--custom-rules`. The constraints will override the infered ones.
```java
// hopper fuzz output --custom-rules path-to-file
// Grammar: 
// func, type : prefix for adding a rule for function or type
// $[0-9]+    : function's i-th argument, or index in array
// [a-zA-Z_]+ : object field
// 0, 128 ..  : integer constants
// "xxxx"     : string constants
// methods    : $len, $range, $null, $non_null, $need_init, $read_file, $write_file, $ret_from, $cast_from, $use, $arr_len, $opaque, $len_factors
// others     :  pointer(&) , option(?), e.g &.$0.len,  `len` field in the pointer's first element
//
// Set one argument in a function to be specific constant
func test_add[$0] = 128
// One argument must be the length of another one
func test_arr[$1] = $len($0)
// Or one field must be the length of another field
func test_arr[$0][len] = $len([$0][name])
// One argument must be in a certain range
func test_arr[$1] = $range(0, $len($0))
// Argument should be non-null
func test_non_null[$0] = $non_null
// Argument should be null
func test_null[$0] = $null
// Argument should be specific string
func test_magic[$0] = "magic"
// Argument should be a file and the file will be read
func test_path[$0] = $read_file
// Argument should be use the value of specific function's return
func test_use[$0] = $ret_from(test_create)
// Argument should be specific type for void pointer. The type should start with *mut or *cosnt.
func test_void[$0] = $cast_from(*mut u8)
// The array suppose has a minimal array length
func test_void[$0][&] = $arr_len(256)
// The array's length is formed by the factors
func fread[$0][&] = $len_factors(1, $2)
// Or
func gzfread[$0][&] = $len_factors($1, $2)
// Field in argument should be specific constant
func test_field[$0][len] = 128
// Deeper fields
func test_field[$0][&.elements.$0] = 128

// One field `len` in a type must be the length of another field `p`
type ArrayWrap[len] = $len(p)
// One nested union `inner_union` in a type must be set to `member2` 
type ComplicatedStruct[inner_union] = $use(member2)
// Type is opaque that used as an opaque pointer
type Partial = $opaque
// A type should be init with specific function
type Partial = $init_with(test_init, 0)

// ctx: set context for specific function
// Add a context for function
ctx test_use[$0] <- test_init
// Add implicit context
ctx test_use[*] <- test_init
// Add optional context that prefered to use
ctx test_use[$0] <- test_init ?
// Add forbidden context
ctx test_use[$0] <- ! test_init

// alias: alias types across different function
alias handleA <- useA($0),createA($ret),freeA($0)

// assert: adding specific assertions for calls
assert test_one == 1
assert test_non_zero != 0

```

### Seeds for bytes arguments
If there is a `seeds` direcotry (Set by `HOPPER_SEED_DIR`), Hopper will try to read files inside it and uses them as the seeds for bytes arguments (e.g. char*). Also, you can indicate the seeds for specific argument via its parameter names, e.g make the subdirectory as `@buf` for parameter whose name is `buf`.

### Logging
Hopper uses Rust's log crate to print log information. The default log level is `INFO`. If you want to print all logging information (`DEBUG` and `TRACE`), you can set the environment `LOG_TYPE` during running Hopper, e.g. `LOG_TYPE=trace ./hopper`.
The detailed logging will be written at `output/fuzzer_r*.log` and `output/harness_r*.log`.

### Reproduce execution
Hopper can reproduce the execution of programs at output directories.

- `hopper-harness` can parse and explain the inputs by Hopper's runtime. It wiil print the internal states during execution in detail.
```
./bin/hopper-harness ./queue/id_000000
```

- `hopper-translate` can translate the input to C source code. The C files can be a witness for reporting issues.
```
./bin/hopper-translate --input ./queue/id_000000  --header path-to/xx.h --output test.c
# then compile it with specific library
gcc -I/path-to-head -L/path-to-lib -l:libcjson.so test.c -o test
```

- `hopper-generator` is able to replay input generation except execution. You can use it to analyse how the input was generated or mutated.
```
./bin/hopper-generator ./queue/id_000000
```

- `hopper-sanitizer` can minimize and verify the crashes generated by Hopper. It excludes crashes that violate constraints and de-duplicate crashes according to call stacks.
```
./bin/hopper-sanitizer
```

## Test
### Test rust code
- Run all testcases
```
RUST_BACKTRACE=1 cargo test -- --nocapture
```

### Testsuite (test libraries)
- [How to run and write testuite](./testsuite/README.md)

### Real world examples
- [Examples](./examples/)

## Evaluating results via source-based code coverage
- Compile the libraies' source code with [LLVM source-based code sanitizer](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html). You should set the compiling flags, e.g. 

```
export CFLAGS="${CFLAGS:-} -fprofile-instr-generate -fcoverage-mapping -gline-tables-only -g"
make
```

- Compile the libraries with `cov` instrumentation mode. e.g.
```
hopper compile --instrument cov --header ./cJSON.h --library ./libcjson_cov.so --output output_cov
```

- Run the interpreter with all generated seed inputs (SEED_DIR).
``` 
# run hopper and use llvm-cov to compute the coverage.
SEED_DIR=./output/queue hopper cov output_cov
```

## Contributing guidelines
We have listed some tasks in [Roadmap](https://github.com/FuzzAnything/hopper/discussions/2).
If you are interested, please feel free to discuss with us and contribute your code.

### Coding
- *Zero* `cargo check` warnning
- *Zero* `cargo clippy` warnning
- *Zero* `FAILED` in `cargo test`
- *Try* to write tests for your code

### Profiling
- [Profiling Rust Applications](https://gist.github.com/KodrAus/97c92c07a90b1fdd6853654357fd557a)
- [Inferno](https://github.com/jonhoo/inferno)

```bash
perf record --call-graph=dwarf ./bin/hopper-fuzzer
# use flamegraph directly
perf script | stackcollapse-perf.pl | rust-unmangle | flamegraph.pl > flame.svg
# use inferno
perf script | inferno-collapse-perf | inferno-flamegraph > flamegraph.svg
```

perf will produce huge intermediate data for analysis, so *do not* run fuzzer more than 2 minutes.

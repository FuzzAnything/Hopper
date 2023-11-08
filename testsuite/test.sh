#!/bin/bash

realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}
BIN_PATH=$(realpath "$0")
TEST_DIR=$(dirname $BIN_PATH)
source ${TEST_DIR}/../tools/style.sh

HOPPER_CC=$TEST_DIR/../install/hopper-clang
HOPPER=$TEST_DIR/../hopper

USAGE="Usage: $(basename $0) [make|compile|build|test|build_all|test_all|help] ...
    make    [dir]      : Make library in test directory. Env USE_LLVM=1 will use hopper's llvm mode.
    compile [dir]      : Compile library as hopper harness.
    build   [dir]      : Make and compile the library into hopper harness.
    test    [dir] [fn] : Run hopper harness for fuzzing test, [fn] is the target function and optional.
    build_all          : Build all libraries.
    test_all           : Test all functions."

CC=${CC:-gcc}
CFLAGS=${CFLAGS:-}
LDFLAGS="-g -fPIC -Wall"

if [[ -v USE_LLVM ]]; then
    CC=${HOPPER_CC}
fi

DY_LIB_NAME=
DY_LDFLAGS=-shared
init_lib_name() {
    LIB_NAME=lib$1
    case "$(uname -s)" in
    Darwin)
        DY_LIB_NAME="${LIB_NAME}.dylib"
        DY_LDFLAGS=-shared
        ;;
    Linux)
        DY_LIB_NAME="${LIB_NAME}.so"
        DY_LDFLAGS=-shared
        ;;
    *)
        error "Unknown os"
        exit 1
        ;;
    esac
}

load_config() {
    DIR=$1
    if [[ -f ${DIR}/config.sh ]]; then
        source ./config.sh
    fi
}

make_clib() {
    DIR=$1
    NAME=$1
    load_config $DIR
    init_lib_name $NAME
    SRC=${NAME}.c
    cmd="${CC} ${CFLAGS} ${LDFLAGS} ${DY_LDFLAGS} -o ${DIR}/${DY_LIB_NAME} ${DIR}/${SRC}"
    info "${cmd}"
    eval ${cmd}
}

compile_hopper() {
    DIR=$1
    NAME=$1
    load_config $DIR
    init_lib_name $NAME
    HEADER=${NAME}.h
    COMPILE_OPTIONS=${COMPILE_OPTIONS:-}
    export HOPPER_TESTSUITE=1
    ${HOPPER} compile ${COMPILE_OPTIONS} \
        --header ${DIR}/${HEADER} \
        --library ${DIR}/${DY_LIB_NAME} \
        --output ${DIR}/output
    eval ${cmd}
}

hopper_test() {
    DIR=$1
    TEST_FN=$2
    load_config $DIR
    rm -rf ${DIR}/output/queue
    rm -rf ${DIR}/output/crashes
    rm -rf ${DIR}/output/hangs
    rm -rf ${DIR}/output/misc
    unset HOPPER_SEED_DIR
    [ -d "${DIR}/seeds" ] && export HOPPER_SEED_DIR=${DIR}/seeds
    unset HOPPER_DICT
    [ -f "${DIR}/dict" ] && export HOPPER_DICT=${DIR}/dict
    COMMENTS=$(grep -Pzo "(\/\/.*\n)*\s*\w+\s*${TEST_FN}\s*\(" ./$DIR/$DIR.h)
    # info "$COMMENTS"
    if [[ $COMMENTS == *"ignore"* ]]; then
        warn "ignore test ${TEST_FN}"
        return 0
    fi
    unset TESTSUITE_ABORT
    if [[ $COMMENTS == *"abort"* ]]; then
        info "${TEST_FN} is expected to be crash (abort)"
        export TESTSUITE_ABORT=1
    fi
    DEP=$(echo "$COMMENTS" | grep -Po 'depend\s*:\s*\K.+')
    info "dependencies: $DEP"
    INFER=$(echo "$COMMENTS" | grep -Po 'infer\s*:\s*\K.+')
    info "infer: $INFER"
    export TESTSUITE_INFER="${INFER}"
    ${HOPPER} fuzz ${DIR}/output \
        --mem-limit=10000 \
        --custom-rules ${DIR}/custom.rule \
        --func-pattern @${TEST_FN},$DEP
    ret_code=$?
    echo "ret_code : ${ret_code}"
    if ((ret_code != 0x69)); then
        warn "test fail"
        exit 1
    fi
    info "test success"
}

usage() {
    warn "$USAGE"
    exit 1
}

CMD=${1:-help}
case ${CMD} in
make)
    if [ $# -ge 2 ]; then
        make_clib $2
    else
        usage
    fi
    ;;
compile)
    if [ $# -ge 2 ]; then
        compile_hopper $2
    else
        usage
    fi
    ;;
test)
    if [ $# -ge 3 ]; then
        hopper_test $2 $3
    elif [ $# -ge 2 ]; then
        dir=$2
        info "test dir ${dir} ..."
        fns=$(grep -wo -E 'test_[a-zA-Z_0-9]*' ./$dir/$dir.h)
        for fn in $fns; do
            info "test fn ${fn}"
            hopper_test $dir $fn
        done
    else
        usage
    fi
    ;;
build)
    if [ $# -ge 2 ]; then
        make_clib $2
        compile_hopper $2
    else
        usage
    fi
    ;;
build_all)
    for dir in $TEST_DIR/*; do
        if [[ -d "$dir" && ! -L "$file" ]]; then
            dir=${dir%*/}  # remove the trailing "/"
            dir=${dir##*/} # print everything after the final "/"
            info "build ${dir} ..."
            make_clib $dir
            COMPILE_OPTIONS="--quiet" compile_hopper $dir
        fi
    done
    ;;
test_all)
    for dir in $TEST_DIR/*; do
        if [[ -d "$dir" && ! -L "$file" ]]; then
            full_path=${dir%*/}  # remove the trailing "/"
            dir=${full_path##*/} # print everything after the final "/"
            info "test dir ${dir} ..."
            fns=$(grep -wo -E 'test_[a-zA-Z_0-9]*' $full_path/$dir.h)
            for fn in $fns; do
                info "test fn ${fn}"
                #LOG_TYPE=warn
                hopper_test $dir $fn
            done
        fi
    done
    ;;
help)
    usage
    ;;
*)
    usage
    ;;
esac

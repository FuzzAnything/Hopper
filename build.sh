#!/bin/bash

realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}
BIN_PATH=$(realpath "$0")
ROOT_DIR=$(dirname $BIN_PATH)
INSTALL_DIR=$ROOT_DIR/install
PATCHELF_VERSION=0.14.5

source ${ROOT_DIR}/tools/style.sh

mkdir -p $INSTALL_DIR
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    info "start install e9path and hopper's e9 plugins ..."
    cd hopper-instrument/e9-mode
    PREFIX=$INSTALL_DIR ./build.sh
    cd ../../

    if [ ! -x $INSTALL_DIR/patchelf ]; then
        info "download patchelf ..."
        cd install
        mkdir -p tmp
        cd tmp
        wget https://github.com/NixOS/patchelf/releases/download/${PATCHELF_VERSION}/patchelf-${PATCHELF_VERSION}-x86_64.tar.gz
        tar -xvf patchelf-${PATCHELF_VERSION}-x86_64.tar.gz
        cp bin/patchelf ../.
        cd ../../
    fi
fi

# info "start install hopper's llvm plugins ..."
# cd hopper-instrument/llvm-mode
# make PREFIX=$INSTALL_DIR

BUILD_TYPE=${BUILD_TYPE:-debug}
# BUILD_TYPE=${BUILD_TYPE:-release}

info "start build and install hopper fuzzer ..."
if [[ "$BUILD_TYPE" == "debug" ]]; then
    cargo build
else
    cargo build --release
fi

ln -sf $ROOT_DIR/target/$BUILD_TYPE/hopper-compiler $INSTALL_DIR/

info "build and install hopper done!"

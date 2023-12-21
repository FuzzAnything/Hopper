#!/bin/bash
#
# Copyright (C) 2021 National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

VERSION=811642cf744ba1726fc34851dc44f4c4df436ce7

SOURCE_DIR=$(pwd)
PREFIX=${PREFIX:-install}

echo "PREFIX: $PREFIX"
echo "PWD: $SOURCE_DIR"
mkdir -p $PREFIX
mkdir -p $PREFIX/tmp

# STEP (1): install e9patch if necessary:
if [ ! -x $PREFIX/tmp/e9patch-$VERSION/e9patch ]
then
    if [ ! -f $PREFIX/tmp/e9patch-$VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading e9patch-$VERSION.zip..."
        wget -O $PREFIX/tmp/e9patch-$VERSION.zip https://github.com/GJDuck/e9patch/archive/$VERSION.zip
    fi
    echo -e "${GREEN}$0${OFF}: extracting e9patch-$VERSION.zip..."
    cd $PREFIX/tmp
    unzip -q e9patch-$VERSION.zip
    echo -e "${GREEN}$0${OFF}: building e9patch..."
    cd e9patch-$VERSION
    echo -e "${GREEN}$0${OFF}: patch e9patch..."
    # only used for windows instrumentation
    patch -p1 <$SOURCE_DIR/e9patch.diff
    ./build.sh
    cp e9patch ../../
    cp e9tool ../../
    echo -e "${GREEN}$0${OFF}: e9patch has been built..."
else
	echo -e "${GREEN}$0${OFF}: using existing e9patch..."
fi

# STEP (2): build the E9Tool plugin:
# build the E9Tool plugin for ELF:
cd $SOURCE_DIR
echo -e "${GREEN}$0${OFF}: building the hopper plugin..."
echo "g++ -std=c++11 -fPIC -shared -o hopper-e9-plugin.so -O2 hopper-e9-plugin.cpp -I ."
g++ -std=c++11 -fPIC -shared -o $PREFIX/hopper-e9-plugin-elf.so -O2 hopper-e9-plugin.cpp \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9tool/
strip $PREFIX/hopper-e9-plugin-elf.so
chmod a-x $PREFIX/hopper-e9-plugin-elf.so
# build the E9Tool plugin for PE:
g++ -std=c++11 -fPIC -shared -o $PREFIX/hopper-e9-plugin-pe.so -O2 hopper-e9-plugin.cpp \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9tool/ -DWINDOWS
strip $PREFIX/hopper-e9-plugin-pe.so
chmod a-x $PREFIX/hopper-e9-plugin-pe.so

# build cmp plugin
# build cmp plugin for ELF:
g++ -std=c++11 -fPIC -shared -o $PREFIX/hopper-instr-plugin-elf.so -O2 hopper-instr-plugin.cpp \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9tool/
strip $PREFIX/hopper-instr-plugin-elf.so
chmod a-x $PREFIX/hopper-instr-plugin-elf.so
# build cmp plugin for PE
g++ -std=c++11 -fPIC -shared -o $PREFIX/hopper-instr-plugin-pe.so -O2 hopper-instr-plugin.cpp \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9tool/ -DWINDOWS
strip $PREFIX/hopper-instr-plugin-pe.so
chmod a-x $PREFIX/hopper-instr-plugin-pe.so

# STEP (3): build the runtime:
# build the runtime for ELF
echo -e "${GREEN}$0${OFF}: building the hopper runtime..."
echo -e "${PREFIX}/tmp/e9patch-${VERSION}/e9compile.sh hopper-e9-rt.c -I ${PREFIX}/tmp/e9patch-${VERSION}/examples/ \
    -I ${PREFIX}/tmp/e9patch-${VERSION}/src/e9patch/ -DNO_GLIBC=1"
$PREFIX/tmp/e9patch-$VERSION/e9compile.sh hopper-e9-rt.c -I $PREFIX/tmp/e9patch-$VERSION/examples/ \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9patch/ -DNO_GLIBC=1
rm hopper-e9-rt.o
chmod a-x hopper-e9-rt
mv hopper-e9-rt $PREFIX/hopper-e9-rt-elf
# build the runtime for PE:
echo -e "${GREEN}$0${OFF}: remember to change HOPPER_PATH_SHMID and HOPPER_INSTR_SHMID in windows.c"
$PREFIX/tmp/e9patch-$VERSION/e9compile.sh hopper-e9-rt.c -I $PREFIX/tmp/e9patch-$VERSION/examples/ \
    -I $PREFIX/tmp/e9patch-$VERSION/src/e9patch/ -DWINDOWS -mabi=ms
rm hopper-e9-rt.o
chmod a-x hopper-e9-rt
mv hopper-e9-rt $PREFIX/hopper-e9-rt-pe

# STEP (4): build the driver:
# g++ -std=c++11 -fPIC -pie -O2 -o e9hopper e9hopper.cpp
# strip e9hopper

echo -e "${GREEN}$0${OFF}: done!"
echo

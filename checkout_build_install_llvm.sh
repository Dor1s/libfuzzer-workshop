#!/bin/bash -eux
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get autoremove -y

sudo apt-get install -y libc6-dev binutils libgcc-5-dev

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git python2.7"
sudo apt-get install -y $LLVM_DEP_PACKAGES

WORK_DIR=$PWD
mkdir -p $WORK_DIR/src

# Checkout
cd $WORK_DIR/src && git clone --depth 1 http://llvm.org/git/llvm.git
cd $WORK_DIR/src/llvm/tools && git clone --depth 1 http://llvm.org/git/clang.git
cd $WORK_DIR/src/llvm/projects && git clone --depth 1 http://llvm.org/git/compiler-rt.git
cd $WORK_DIR/src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxx.git
cd $WORK_DIR/src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxxabi.git

# Uncomment if you want *fresh* libFuzzer from checkouted repository.
#rm -r $WORK_DIR/libFuzzer/Fuzzer
#cp -r $WORK_DIR/src/llvm/projects/compiler-rt/lib/fuzzer/ $WORK_DIR/libFuzzer/Fuzzer

# Build & Install
mkdir -p $WORK_DIR/work/llvm
cd $WORK_DIR/work/llvm

# Consider adding of -DCMAKE_INSTALL_PREFIX=%PATH% flag, if you do not want to
# install fresh llvm binaries into standard system paths.
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      $WORK_DIR/src/llvm
ninja -j$(nproc)
sudo ninja install
rm -rf $WORK_DIR/work/llvm



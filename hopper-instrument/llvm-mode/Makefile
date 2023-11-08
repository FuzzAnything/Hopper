#
# american fuzzy lop - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# LLVM integration design comes from Laszlo Szekeres.
#
# Copyright 2015, 2016 Google LLC All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= install

LLVM_CONFIG ?= llvm-config

CFLAGS      ?= -O3 -funroll-loops -I./include
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign 

ifdef AFL_TRACE_PC
  CFLAGS    += -DUSE_TRACE_PC=1
endif

CXXFLAGS    ?= -O3 -funroll-loops -I./include
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -Wno-variadic-macros

# Mark nodelete to work around unload bug in upstream LLVM 5.0+
CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

# User teor2345 reports that this is required to make things work on MacOS X.
ifeq "$(shell uname)" "Darwin"
  CLANG_LFL += -Wl,-flat_namespace -Wl,-undefined,suppress
else
  CLANG_LFL += -Wl,-znodelete
endif

# We were using llvm-config --bindir to get the location of clang, but
# this seems to be busted on some distros, so using the one in $PATH is
# probably better.

ifeq "$(origin CC)" "default"
  CC         = clang
  CXX        = clang++
endif

ifndef AFL_TRACE_PC
  PROGS      = $(PREFIX)/hopper-clang $(PREFIX)/hopper-llvm-pass.so $(PREFIX)/hopper-llvm-rt.o $(PREFIX)/hopper-llvm-rt-32.o $(PREFIX)/hopper-llvm-rt-64.o
else
  PROGS      = $(PREFIX)/hopper-clang $(PREFIX)/hopper-llvm-rt.o $(PREFIX)/hopper-llvm-rt-32.o $(PREFIX)/hopper-llvm-rt-64.o
endif

all: test_deps $(PROGS) all_done

test_deps:
	@echo "[*] PREFIX : ${PREFIX}"
	@mkdir -p $(PREFIX)
ifndef AFL_TRACE_PC
	@echo "[*] Checking for working 'llvm-config'..."
	@which $(LLVM_CONFIG) >/dev/null 2>&1 || ( echo "[-] Oops, can't find 'llvm-config'. Install clang or set \$$LLVM_CONFIG or \$$PATH beforehand."; echo "    (Sometimes, the binary will be named llvm-config-3.5 or something like that.)"; exit 1 )
else
	@echo "[!] Note: using -fsanitize=trace-pc mode (this will fail with older LLVM)."
endif
	@echo "[*] Checking for working '$(CC)'..."
	@which $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
	@echo "[+] All set and ready to build."

$(PREFIX)/hopper-clang: hopper-clang.c | test_deps
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf $(PREFIX)/hopper-clang $(PREFIX)/hopper-clang++

$(PREFIX)/hopper-llvm-pass.so: hopper-llvm-pass.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

$(PREFIX)/hopper-llvm-rt.o: hopper-llvm-rt.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(PREFIX)/hopper-llvm-rt-32.o: hopper-llvm-rt.c | test_deps
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CC) $(CFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

$(PREFIX)/hopper-llvm-rt-64.o: hopper-llvm-rt.c | test_deps
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

all_done: 
	@echo "[+] All done! You can now use 'hopper-clang' to compile programs."

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* test-instr .test-instr0 .test-instr1 
	rm -f $(PROGS) $(PREFIX)/afl-clang-fast++
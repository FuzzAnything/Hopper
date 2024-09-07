/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode wrapper for clang
   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This program is a drop-in replacement for clang, similar in most respects
   to ../hopper-gcc. It tries to figure out compilation mode, adds a bunch
   of flags, and then calls the real compiler.
*/

#define HOPPER_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc_inl.h"

static u8* obj_path;       /* Path to runtime libraries         */
static u8** cc_params;     /* Parameters passed to the real CC  */
static u32 cc_par_cnt = 1; /* Param count, including argv0      */

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8* argv0) {
  u8* hopper_path = getenv("HOPPER_PATH");
  u8 *slash, *tmp;

  if (hopper_path) {
    tmp = alloc_printf("%s/libHopperPass.so", hopper_path);

    if (!access(tmp, R_OK)) {
      obj_path = hopper_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
  }

  slash = strrchr(argv0, '/');

  if (slash) {
    u8* dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/libHopperPass.so", dir);

    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);
  } else {
    char* procname = NULL;
#if defined(__FreeBSD__) || defined(__DragonFly__)
    procname = "/proc/curproc/file";
#elif defined(__linux__) || defined(__ANDROID__)
    procname = "/proc/self/exe";
#elif defined(__NetBSD__)
    procname = "/proc/curproc/exe";
#endif
    if (procname) {
#define PATH_MAX 4096
      char exepath[PATH_MAX];
      ssize_t exepath_len = readlink(procname, exepath, sizeof(exepath));
      if (exepath_len > 0 && exepath_len < PATH_MAX) {
        exepath[exepath_len] = 0;
        slash = strrchr(exepath, '/');

        if (slash) {
          *slash = 0;
          tmp = alloc_printf("%s/libHopperPass.so", exepath);

          if (!access(tmp, R_OK)) {
            obj_path = exepath;
            ck_free(tmp);
            return;
          }

          ck_free(tmp);
          ck_free(exepath);
        }
      }
    }
  }

  FATAL("Unable to find 'libHopperPass.so'. Please set HOPPER_PATH");
}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {
  u8 fortify_set = 0, asan_set = 0, x_set = 0, bit_mode = 0;
  u8* name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    name++;

  if (!strcmp(name, "hopper-clang++")) {
    u8* alt_cxx = getenv("HOPPER_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
  } else {
    u8* alt_cc = getenv("HOPPER_CC");
    cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
  }

  // Do not support TRACE_PC

  // printf("version: %d\n", LLVM_VERSION_MAJOR);
  /*
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = alloc_printf("%s/libHopperPrePass.so", obj_path);
  */
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = alloc_printf("%s/libHopperPass.so", obj_path);
#if LLVM_VERSION_MAJOR >= 11
/*
#if LLVM_VERSION_MAJOR < 16
  cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
#endif
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] =
      alloc_printf("-fpass-plugin=%s/libHopperPrePass.so", obj_path);
      */
#if LLVM_VERSION_MAJOR < 16
  cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
#endif
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] =
      alloc_printf("-fpass-plugin=%s/libHopperPass.so", obj_path);
#endif

  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  while (--argc) {
    u8* cur = *(++argv);

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
      continue;

    cc_params[cc_par_cnt++] = cur;
  }

  if (getenv("HOPPER_HARDEN")) {
    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set) cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
  }

  if (!asan_set) {
    if (getenv("HOPPER_USE_ASAN")) {
      if (getenv("HOPPER_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("HOPPER_HARDEN"))
        FATAL("ASAN and HOPPER_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("HOPPER_USE_MSAN")) {
      if (getenv("HOPPER_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("HOPPER_HARDEN"))
        FATAL("MSAN and HOPPER_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";
    }
  }

  if (!getenv("HOPPER_DONT_OPTIMIZE")) {
    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";
  }

  if (getenv("HOPPER_NO_BUILTIN")) {
    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
  }

  cc_params[cc_par_cnt++] = "-D__HOPPER_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__HOPPER_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by hopper-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __hopper_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  if (x_set) {
    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";
  }

  cc_params[cc_par_cnt] = NULL;
}

/* Main entry point */

int main(int argc, char** argv) {
#ifndef __ANDROID__
  find_obj(argv[0]);
#endif

  if (argc < 2) {
    SAYF(
        "\n"
        "This is a helper application for hopper-fuzz. It serves as a drop-in "
        "replacement\n"
        "for clang, letting you recompile third-party code with the required "
        "runtime\n"
        "instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=hopper-clang ./configure\n"
        "  CXX=hopper-clang++ ./configure\n\n"

        "In contrast to the traditional hopper-clang tool, this version is "
        "implemented as\n"
        "an LLVM pass and tends to offer improved performance with slow "
        "programs.\n\n"

        "You can specify custom next-stage toolchain via HOPPER_CC and "
        "HOPPER_CXX. Setting\n"
        "HOPPER_HARDEN enables hardening optimizations in the compiled "
        "code.\n\n");

    exit(1);
  }

  edit_params(argc, argv);

  for (int i = 0; i < cc_par_cnt; i++) {
    printf("%s ", cc_params[i]);
  }
  printf("\n");

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;
}
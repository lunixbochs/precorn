#ifndef PRECORN_INJECT_H
#define PRECORN_INJECT_H

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <ucontext.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    ucontext_t ucp;
    uint64_t entry;

    uint64_t stack_base, stack_size;

    csh cs;
    uc_engine *uc;
    uc_hook code_hook,
            segfault_hook,
            intr_hook,
            syscall_hook;

    uint64_t abi_reg[7];
    uint64_t *abi_reg_ptr[7];

    bool started;
    int exit_reason;
} precorn_context;

enum {
    EXIT_NONE,
    EXIT_SET_FS,
    EXIT_SET_GS,
};

extern precorn_context ctx;

#endif

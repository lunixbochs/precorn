#ifndef PRECORN_H
#define PRECORN_H

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <ucontext.h>
#include <stdint.h>
#include <stdbool.h>

#define uc_check(...) do {uc_err err; if ((err = __VA_ARGS__)) { printf("%s failed: %s\n", #__VA_ARGS__, uc_strerror(err)); exit(1); }} while (0);

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

    bool pivoting, started;
    int exit_reason;
} precorn_ctx;

enum {
    EXIT_NONE,
    EXIT_SET_FS,
    EXIT_SET_GS,
};

extern precorn_ctx ctx;
extern void host_uc_init(precorn_ctx *ctx);
extern bool host_trampoline(precorn_ctx *ctx);
extern void host_setup(precorn_ctx *ctx, uint64_t run, uint64_t stack_top);

#endif

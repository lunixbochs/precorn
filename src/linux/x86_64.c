#include "../precorn.h"
#include "../x86_64.h"

#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern int arch_prctl(int code, unsigned long *addr);

static int syscall_abi[] = {UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9};

// This function is called to handle the SYSCALL instruction.
// It currently:
//  - watches mmap() to pre-map memory into the guest
//  - watches arch_prctl() to update segment registers in the guest
static void hook_syscall(uc_engine *uc, void *user) {
    uc_check(uc_reg_read_batch(uc, syscall_abi, (void **)ctx.abi_reg_ptr, 7));
    uint64_t *r = &ctx.abi_reg[0];

    uint64_t ret = 0;
    ret = syscall(r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
    // printf("sys %d = %zd\n", (int)r[0], ret);
    switch (r[0]) {
    case SYS_arch_prctl:
        if (ret == 0) {
            if (r[1] == ARCH_SET_FS) {
                ctx.exit_reason = EXIT_SET_FS;
                uc_emu_stop(uc);
            } else if (r[1] == ARCH_SET_GS) {
                ctx.exit_reason = EXIT_SET_GS;
                uc_emu_stop(uc);
            }
        }
    case SYS_mmap:
        if (ret != (uint64_t)MAP_FAILED) {
            uc_mem_map_ptr(uc, ret, r[2], UC_PROT_ALL, (void *)ret);
        }
        break;
    }
    uc_reg_write(uc, UC_X86_REG_RAX, &ret);
}

// copy TLS registers to emulator
void set_tls(precorn_ctx *ctx) {
    uint64_t fs, gs;
    arch_prctl(ARCH_GET_FS, &fs);
    arch_prctl(ARCH_GET_FS, &gs);
    uc_check(wrmsr(ctx->uc, 0xC0000100, fs));
    uc_check(wrmsr(ctx->uc, 0xC0000101, gs));
}

void host_uc_init(precorn_ctx *ctx) {
    uc_check(uc_open(UC_ARCH_X86, UC_MODE_64, &ctx->uc));
    uc_hook_add(ctx->uc, &ctx->syscall_hook, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);
    set_tls(ctx);
}

bool host_trampoline(precorn_ctx *ctx) {
    switch (ctx->exit_reason) {
        case EXIT_SET_FS:
        case EXIT_SET_GS:
            set_tls(ctx);
            return true;
    }
    return false;
}

void host_setup(precorn_ctx *ctx, uint64_t run, uint64_t stack_top) {
    // copy host registers to emulator
    ctx->entry = ctx->ucp.uc_mcontext.gregs[REG_RIP];
#define set_reg(_enum) uc_check(uc_reg_write(ctx->uc, UC_X86_REG_##_enum, &ctx->ucp.uc_mcontext.gregs[REG_##_enum]));
    set_reg(RAX); set_reg(RBX); set_reg(RCX);
    set_reg(RDX); set_reg(RDI); set_reg(RSI);
    set_reg(RBP); set_reg(RSP);
    set_reg(R8); set_reg(R9); set_reg(R10); set_reg(R11);
    set_reg(R12); set_reg(R13); set_reg(R14); set_reg(R15);
#undef set_reg
    // update our saved context to jump into the run() function with the new stack
    ctx->ucp.uc_mcontext.gregs[REG_RIP] = run;
    ctx->ucp.uc_mcontext.gregs[REG_RSP] = stack_top;
}

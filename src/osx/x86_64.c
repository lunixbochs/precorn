#include <sys/syscall.h>
#include <unistd.h>

#include "../precorn.h"
#include "../x86_64.h"

static int syscall_abi[] = {UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9};

// copy TLS registers to emulator
void set_tls(precorn_ctx *ctx) {
    uint64_t fs, gs;
    // TODO: get FS/GS on OS X
    uc_check(wrmsr(ctx->uc, 0xC0000100, fs));
    uc_check(wrmsr(ctx->uc, 0xC0000101, gs));
}

static void hook_syscall(uc_engine *uc, void *user) {
    uc_check(uc_reg_read_batch(uc, syscall_abi, (void **)ctx.abi_reg_ptr, 7));
    volatile uint64_t *r = &ctx.abi_reg[0];

    uint64_t register rax __asm__("rax") = r[0],
                      rdi __asm__("rdi") = r[1],
                      rsi __asm__("rsi") = r[2],
                      rdx __asm__("rdx") = r[3],
                      r10 __asm__("r10") = r[4],
                      r8  __asm__("r8")  = r[5],
                      r9  __asm__("r9")  = r[6];
    __asm__(
        "syscall"
        :"+r"(rax)
        :"r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        :"rax"
    );
    uint64_t ret = rax;
    printf("sys %d = %zd\n", (int)r[0], ret);
    uc_reg_write(uc, UC_X86_REG_RAX, &ret);
}

// set up unicorn, syscall hook, and TLS
void host_uc_init(precorn_ctx *ctx) {
    uc_check(uc_open(UC_ARCH_X86, UC_MODE_64, &ctx->uc));
    uc_hook_add(ctx->uc, &ctx->syscall_hook, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);
    set_tls(ctx);
}

// called after uc_emu_start() exits
bool host_trampoline(precorn_ctx *ctx) {
    return false;
}

void host_setup(precorn_ctx *ctx, uint64_t run, uint64_t stack_top) {
    // copy host registers to emulator
    ctx->entry = ctx->ucp.uc_mcontext->__ss.__rip;
#define set_reg(_enum, attr) uc_check(uc_reg_write(ctx->uc, UC_X86_REG_##_enum, &ctx->ucp.uc_mcontext->__ss.__##attr));
    set_reg(RAX, rax); set_reg(RBX, rbx); set_reg(RCX, rcx);
    set_reg(RDX, rdx); set_reg(RDI, rdi); set_reg(RSI, rsi);
    set_reg(RBP, rbp); set_reg(RSP, rsp);
    set_reg(R8, r8); set_reg(R9, r9); set_reg(R10, r10);
    set_reg(R11, r11); set_reg(R12, r12); set_reg(R13, r13);
    set_reg(R14, r14); set_reg(R15, r15);
#undef set_reg
    // update our saved context to jump into the run() function with the new stack
    ctx->ucp.uc_mcontext->__ss.__rip = run;
    ctx->ucp.uc_mcontext->__ss.__rsp = stack_top;
}

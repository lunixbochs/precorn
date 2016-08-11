// This code is where the magic happens.

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "precorn.h"

#include <malloc.h>
#include "malloc.h"

#define check(...) do {uc_err err; if ((err = __VA_ARGS__)) { printf("%s failed: %s\n", #__VA_ARGS__, uc_strerror(err)); }} while (0);

extern int arch_prctl(int code, unsigned long *addr);
extern void glib_memhook();

static int syscall_abi[] = {UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9};

precorn_context ctx = {0};

// On guest memory fault, map the corresponding page from host memory into the guest.
static bool hook_segfault(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user) {
    // assume null pointer deref
    if (addr < 0x4000) {
        printf("invalid access: 0x%zx\n", addr);
        return false;
    }
    size = (size + 0xfff) & ~0xfff;
    addr &= ~0xfff;
    check(uc_mem_map_ptr(uc, addr, size, UC_PROT_ALL, (void *)addr));
    return true;
}

// This function is called to handle the SYSCALL instruction.
// It currently:
//  - watches mmap() to pre-map memory into the guest
//  - watches arch_prctl() to update segment registers in the guest
static void hook_syscall(uc_engine *uc, void *user) {
    check(uc_reg_read_batch(uc, syscall_abi, (void **)ctx.abi_reg_ptr, 7));
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

static void hook_intr(uc_engine *uc, int intno, void *user) {
    printf("interrupt: %d\n", intno);
}

// map, run, then unmap shellcode for the WRMSR instruction
// TODO: this clobbers RAX, RDX, RCX (but the syscall promises to only clobber RAX)
// this is not yet a problem because it's only called before emulation start
uc_err wrmsr(uc_engine *uc, uint64_t msr, uint64_t value) {
    uc_err err = 0;
    uint64_t tmp = value & 0xFFFFFFFF;
    if ((err = uc_reg_write(uc, UC_X86_REG_RAX, &tmp)))
        return err;

    tmp = (value >> 32) & 0xFFFFFFFF;
    if ((err = uc_reg_write(uc, UC_X86_REG_RDX, &tmp)))
        return err;

    tmp = msr & 0xFFFFFFFF;
    if ((err = uc_reg_write(uc, UC_X86_REG_RCX, &tmp)))
        return err;

    uint8_t wrmsr[] = {0x0f, 0x30};
    uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, 0x1000, wrmsr, 2);
    err = uc_emu_start(uc, 0x1000, 0x1002, 0, 0);
    uc_mem_unmap(uc, 0x1000, 0x1000);
    return err;
}

void set_tls() {
    uint64_t fs, gs;
    arch_prctl(ARCH_GET_FS, &fs);
    arch_prctl(ARCH_GET_FS, &gs);
    check(wrmsr(ctx.uc, 0xC0000100, fs));
    check(wrmsr(ctx.uc, 0xC0000101, gs));
}

static void run() {
    // hook guest segfaults to identity map the surrounding page into the guest
    uc_hook_add(ctx.uc, &ctx.segfault_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_segfault, NULL, 1, 0);

    // hook_intr will be required for 32-bit support
    // uc_hook_add(ctx.uc, &ctx.intr_hook, UC_HOOK_INTR, hook_intr, NULL, 1, 0);
    
    // hook_syscall is used to proxy syscalls to the host
    uc_hook_add(ctx.uc, &ctx.syscall_hook, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

    // This sets up pointers for the faster Unicorn uc_reg_read_batch() API
    for (int i = 0; i < 7; i++) {
        ctx.abi_reg_ptr[i] = &ctx.abi_reg[i];
    }

    ctx.started = true;
    uint64_t ip = ctx.entry;
    // This is a while loop so some operations can "trampoline" - restart emulation to perform some top-level operation.
    // For example, the easiest way to change FS and GS on x86_64 guests in Unicorn currently requires mapping and running shellcode, which can't be done while emulation is running.
    while (1) {
        // printf("starting at 0x%zx\n", ip);
        check(uc_emu_start(ctx.uc, ip, 0, 0, 0));
        uc_reg_read(ctx.uc, UC_X86_REG_RIP, &ip);
        switch (ctx.exit_reason) {
            case EXIT_SET_FS:
            case EXIT_SET_GS:
                set_tls();
                continue;
        }
        break;
    }
    exit(0);
}

__attribute__((constructor))
void pivot() {
    // hook glib allocator to fix glibc reentrancy problems in Unicorn
    // see glib_hooks.c for more information
    glib_memhook();

    // create the guest emulator
    check(uc_open(UC_ARCH_X86, UC_MODE_64, &ctx.uc));

    // save current host registers using ucontext api
    getcontext(&ctx.ucp);

    // the instruction pointer in the guest will start here
    // so we use a static counter to ensure the second time this code path is taken, it returns
    static int counter = 1;
    switch (counter++) {
    case 1:
        ctx.entry = ctx.ucp.uc_mcontext.gregs[REG_RIP];
#define set_reg(_enum) check(uc_reg_write(ctx.uc, UC_X86_REG_##_enum, &ctx.ucp.uc_mcontext.gregs[REG_##_enum]));
        set_reg(RAX); set_reg(RBX); set_reg(RCX);
        set_reg(RDX); set_reg(RDI); set_reg(RSI);
        set_reg(RBP); set_reg(RSP);
        set_reg(R8); set_reg(R9); set_reg(R10); set_reg(R11);
        set_reg(R12); set_reg(R13); set_reg(R14); set_reg(R15);
#undef set_reg
        break;
    default:
        // the guest will path through here
        return;
    }

    // copy FS/GS (thread-local storage registers) to the guest
    set_tls();

    // allocate a new stack for the host
    size_t ssize = 1 * 1024 * 1024;
    uintptr_t stack = (uintptr_t)calloc(1, ssize);
    uintptr_t stack_top = ((stack + ssize) & ~15) - sizeof(void *);
    ctx.ucp.uc_stack.ss_sp = (void *)stack;
    ctx.ucp.uc_stack.ss_size = ssize;
    ctx.ucp.uc_link = NULL;

    ctx.stack_base = stack;
    ctx.stack_size = ssize;

    // update our saved context to jump into the run() function with the new stack
    ctx.ucp.uc_mcontext.gregs[REG_RIP] = (uint64_t)run;
    ctx.ucp.uc_mcontext.gregs[REG_RSP] = stack_top;
    // pivot to the run function (this will never return, as run calls exit())
    setcontext(&ctx.ucp);
    return;
}

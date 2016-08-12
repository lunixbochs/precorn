#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "precorn.h"

#include <malloc.h>
#include "malloc.h"

#include <capstone/capstone.h>

precorn_ctx ctx = {0};

// On guest memory fault, map the corresponding page from host memory into the guest.
static bool hook_segfault(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user) {
    // assume null pointer deref
    if (addr < 0x4000) {
        printf("invalid access: 0x%zx\n", addr);
        return false;
    }
    size = (size + 0xfff) & ~0xfff;
    addr &= ~0xfff;
    uc_check(uc_mem_map_ptr(uc, addr, size, UC_PROT_ALL, (void *)addr));
    return true;
}

static void pdis(void *data, uint64_t addr, uint32_t size) {
    char buf[1025];

    cs_insn *dis, *ins;
    int count = cs_disasm(ctx.cs, data, size, addr, 0, &dis);
    for (int i = 0; i < count; i++) {
        ins = &dis[i];
        // normal printf isn't reentrant
        int len = snprintf(buf, 1024, "0x%08zx: %s %s\n", ins->address, ins->mnemonic, ins->op_str);
        if (len > 0) write(1, buf, len);
    }
}

static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user) {
    uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uint8_t code[32];
    if (size > 32) {
        printf("0x%zx: code too large: %d\n", addr, size);
        return;
    }
    uc_check(uc_mem_read(ctx.uc, addr, code, size));
    pdis(code, addr, size);
}

static void run() {
    cs_open(CS_ARCH_X86, CS_MODE_64, &ctx.cs);
    uc_hook_add(ctx.uc, &ctx.code_hook, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // hook guest segfaults to identity map the surrounding page into the guest
    uc_hook_add(ctx.uc, &ctx.segfault_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_segfault, NULL, 1, 0);

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
        uc_check(uc_emu_start(ctx.uc, ip, 0, 0, 0));
        uc_reg_read(ctx.uc, UC_X86_REG_RIP, &ip);
        if (host_trampoline(&ctx)) {
            continue;
        }
        break;
    }
    exit(0);
}

extern void alloc_init();

__attribute__((constructor))
void pivot() {
    ctx.pivoting = true;
    // we hook glibc allocator to fix reentrancy problems in Unicorn
    // see alloc_hook.c for more information
    alloc_init();

    // create the emulator
    host_uc_init(&ctx);

    // save current host registers using ucontext api
    getcontext(&ctx.ucp);

    // the instruction pointer in the guest will start after getcontext();
    // so we use a static counter to ensure the second time this code path is taken, it returns
    static int counter = 1;
    switch (counter++) {
    case 1:
        // allocate a new stack for the host
        ctx.stack_size = 1 * 1024 * 1024;
        ctx.stack_base = (uint64_t)calloc(1, ctx.stack_size);
        uint64_t stack_top = ((ctx.stack_base + ctx.stack_size) & ~15) - sizeof(void *);
        ctx.ucp.uc_link = NULL;

        // set up registers and the ucontext to jump to run()
        host_setup(&ctx, (uint64_t)run, stack_top);
        break;
    default:
        // the guest will return here
        return;
    }

    // pivot to the run function (this will never return, as run calls exit())
    setcontext(&ctx.ucp);
    return;
}

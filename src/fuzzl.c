#define _XOPEN_SOURCE

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

#include <unicorn/unicorn.h>

#define check(...) do {uc_err err; if ((err = __VA_ARGS__)) { printf("%s failed: %s\n", #__VA_ARGS__, uc_strerror(err)); }} while (0);

static void proxy_map_all(uc_engine *uc) {
    mach_port_t port = mach_task_self();
    mach_msg_type_number_t count;
    mach_port_t object_name;
    mach_vm_address_t address = 1, prev_address = 1;
    mach_vm_size_t vm_size;
    vm_region_basic_info_data_64_t info;

    typedef struct {
        uint64_t addr, size;
        int prot;
    } save_addr;
    size_t addr_count = 0;

    save_addr *addrs = malloc(10000 * sizeof(save_addr));
    kern_return_t err;
    while (1) {
        count = VM_REGION_BASIC_INFO_COUNT_64;
        err = mach_vm_region(port, &address, &vm_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
        if (err != KERN_SUCCESS) {
            printf("mach_vm_region error\n");
            break;
        }
        save_addr *tmp = &addrs[addr_count++];
        tmp->addr = address;
        tmp->size = vm_size;
        tmp->prot = info.protection;

        prev_address = address;
        address += vm_size;
        // stop on wrap
        if (address < prev_address) {
            break;
        }
    }
    for (size_t i = 0; i < addr_count; i++) {
        save_addr *tmp = &addrs[i];
        if (tmp->addr == (uint64_t)addrs) continue;
        // TODO: are the prots the same?
        check(uc_mem_map_ptr(uc, tmp->addr, tmp->size, UC_PROT_ALL, (void *)address));
    }
    free(addrs);
}

static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user) {
    printf("exec @0x%llx\n", addr);
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user) {
    printf("invalid mem: 0x%llx\n", addr);
    return false;
}

static void hook_syscall(uc_engine *uc, void *user) {
    uint64_t rax;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    printf("syscall: %lld\n", rax);
}

static ucontext_t ucp_main;
static uc_engine *uc;
static uint64_t set_rip;

static void run() {
    uc_hook hh;
    uc_hook_add(uc, &hh, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_hook_add(uc, &hh, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid, NULL, 1, 0);
    // uc_hook_add(uc, &hh, UC_HOOK_INTR, hook_intr, NULL, 1, 0);
    uc_hook_add(uc, &hh, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

    // uint64_t rip = ucp_main.uc_mcontext->__ss.__rip;
    uint64_t rip = set_rip;
    printf("emulating at: 0x%llx\n", rip);

    uint8_t buf[32] = {0};
    printf("dumping RIP\n");
    check(uc_mem_read(uc, rip, buf, 8));
    for (int i = 0; i < 8; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    printf("running\n");
    check(uc_emu_start(uc, rip, 0, 0, 0));

    uc_reg_read(uc, UC_X86_REG_RAX, &rip);
    exit(0);
}

__attribute__((constructor))
void fuzzl() {
    check(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    // map zee memory
    proxy_map_all(uc);

    // save everything
    ucontext_t ucp;
    getcontext(&ucp);
    printf("old rip: 0x%llx\n", ucp.uc_mcontext->__ss.__rip);
    // TODO: gotta pivot stack still
#define set_reg(_enum, attr) check(uc_reg_write(uc, UC_X86_REG_##_enum, &ucp.uc_mcontext->__ss.__##attr));
    set_reg(RAX, rax);
    set_reg(RBX, rbx);
    set_reg(RCX, rcx);
    set_reg(RDX, rdx);
    set_reg(RDI, rdi);
    set_reg(RSI, rsi);
    set_reg(RBP, rbp);
    set_reg(RSP, rsp);
    set_reg(R8, r8);
    set_reg(R9, r9);
    set_reg(R10, r10);
    set_reg(R11, r11);
    set_reg(R12, r12);
    set_reg(R13, r13);
    set_reg(R14, r14);
    set_reg(R15, r15);
#undef set_reg

    // TODO: do wrmsr in the emulator for GS
    // set_reg(RAX, cs);
    // set_reg(RAX, fs);
    // set_reg(RAX, gs);

    size_t ssize = 1 * 1024 * 1024;
    uintptr_t stack = (uintptr_t)calloc(1, ssize);
    printf("0x%lx\n", stack);
    uintptr_t stack_top = ((stack + ssize) & ~15) - sizeof(void *);
    ucp.uc_stack.ss_sp = (void *)stack;
    ucp.uc_stack.ss_size = ssize;
    ucp.uc_link = NULL;

    ucp.uc_mcontext->__ss.__rip = (uint64_t)run;
    ucp.uc_mcontext->__ss.__rsp = stack_top;
    set_rip = (uint64_t)&&label;
    setcontext(&ucp);

    /*
    register uint64_t rsp __asm__("rsp");
    register uint64_t rbp __asm__("rbp");
    // eh hopefully the other registers will sort themselves out
    uint64_t tmp = rsp;
    check(uc_reg_write(uc, UC_X86_REG_RSP, &tmp));
    tmp = rbp;
    check(uc_reg_write(uc, UC_X86_REG_RBP, &tmp));
    check(uc_emu_start(uc, (uint64_t)&&label, 0, 0, 0));
    */
label:
    return;
}

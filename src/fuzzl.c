#define _XOPEN_SOURCE

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

#include <unicorn/unicorn.h>

#define check(...) do {uc_err err; if ((err = __VA_ARGS__)) { printf("%s failed: %s\n", #__VA_ARGS__, uc_strerror(err)); exit(1); }} while (0);

static void proxy_map_all(uc_engine *uc) {
    mach_port_t port = mach_task_self();
    mach_msg_type_number_t count;
    mach_port_t object_name;
    mach_vm_address_t address = 1, prev_address = 1;
    mach_vm_size_t vm_size;
    vm_region_basic_info_data_64_t info;

    kern_return_t err;
    while (1) {
        err = mach_vm_region(port, &address, &vm_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
        if (err != KERN_SUCCESS) {
            printf("mach_vm_region error\n");
            return;
        }
        // printf("mapping 0x%llx-0x%llx\n", address, vm_size);
        // TODO: are the prots the same?
        check(uc_mem_map_ptr(uc, address, vm_size, UC_PROT_ALL, (void *)address));

        prev_address = address;
        address += vm_size;
        // stop on wrap
        if (address < prev_address) {
            break;
        }
    }
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
}

static void run(uc_engine *uc, uint64_t rip) {
    printf("HOLD MY BEER\n");
    fflush(stdout);
    check(uc_emu_start(uc, rip, 0, 0, 0));
    exit(0);
}

__attribute__((constructor))
void fuzzl() {
    uc_engine *uc;
    check(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    // map zee memory
    proxy_map_all(uc);

    // save everything
    ucontext_t ucp;
    getcontext(&ucp);
    // TODO: gotta pivot stack still
#define set_reg(_enum, attr) check(uc_reg_write(uc, UC_X86_REG_##_enum, &ucp.uc_mcontext->__ss.__##attr));
    set_reg(RAX, rax);
    set_reg(RAX, rbx);
    set_reg(RAX, rcx);
    set_reg(RAX, rdx);
    set_reg(RAX, rdi);
    set_reg(RAX, rsi);
    set_reg(RAX, rbp);
    set_reg(RAX, rsp);
    set_reg(RAX, r8);
    set_reg(RAX, r9);
    set_reg(RAX, r10);
    set_reg(RAX, r11);
    set_reg(RAX, r12);
    set_reg(RAX, r13);
    set_reg(RAX, r14);
    set_reg(RAX, r15);
#undef set_reg

    // TODO: do wrmsr in the emulator for GS
    // set_reg(RAX, cs);
    // set_reg(RAX, fs);
    // set_reg(RAX, gs);

    makecontext(&ucp, run, 2, uc, &&label);

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

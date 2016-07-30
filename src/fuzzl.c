#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>

#define check(...) do {uc_err err; if ((err = __VA_ARGS__)) { printf("%s failed: %s\n", #__VA_ARGS__, uc_strerror(err)); }} while (0);

void proxy_map_all(uc_engine *uc) {
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

__attribute__((constructor))
void fuzzl() {
    uc_engine *uc;
    check(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    // map zee memory
    proxy_map_all(uc);

    register uint64_t rsp __asm__("rsp");
    register uint64_t rbp __asm__("rbp");
    // eh hopefully the other registers will sort themselves out
    uint64_t tmp = rsp;
    check(uc_reg_write(uc, UC_X86_REG_RSP, &tmp));
    tmp = rbp;
    check(uc_reg_write(uc, UC_X86_REG_RBP, &tmp));
    check(uc_emu_start(uc, (uint64_t)&&label, 0, 0, 0));
label:
    return;
}

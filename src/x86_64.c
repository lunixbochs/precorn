#include <unicorn/unicorn.h>
#include <stdint.h>

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

#include <unicorn/unicorn.h>
#include <stdint.h>

uc_err wrmsr(uc_engine *uc, uint64_t msr, uint64_t value);

#include <unicorn/unicorn.h>
#include <stdint.h>

#include "precorn.h"

uc_err wrmsr(uc_engine *uc, uint64_t msr, uint64_t value);
void x86_64_set_tls(precorn_ctx *ctx);

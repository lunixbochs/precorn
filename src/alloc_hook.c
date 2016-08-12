// This file works around the fact glibc malloc is not reentrant.
// We use the same libc and entire address space on host and guest to simplify setup.
// If QEMU (Unicorn) needs to allocate memory while emulating the guest malloc() function,
// the memory manager lock will already be held, so it will deadlock.
//
// On glib before 2.46, it was possible to replace the entire allocator, so we use that to give Unicorn
// an alternate memory allocator, removing the need to acquire the guest's allocator lock.

#include <dlfcn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "precorn.h"
#include "malloc.h"

// we check is_host() so glib in the guest doesn't break. we only need to fix unicorn's allocator.
static bool is_host() {
    int bogus = 0;
    uint64_t sp = (uint64_t)&bogus;
    if (ctx.pivoting && (ctx.stack_base == 0 || (sp >= ctx.stack_base && sp < ctx.stack_base + ctx.stack_size)))
        return true;
    return false;
}
static int init = 0;
static void *(*orig_malloc)(size_t size) = NULL;
static void *(*orig_realloc)(void *ptr, size_t size) = NULL;
static void (*orig_free)(void *ptr) = NULL;
static void *(*orig_calloc)(size_t nelem, size_t size) = NULL;

void alloc_init() {
    orig_malloc = dlsym(RTLD_NEXT, "malloc");
    orig_realloc = dlsym(RTLD_NEXT, "realloc");
    orig_free = dlsym(RTLD_NEXT, "free");
    orig_calloc = dlsym(RTLD_NEXT, "calloc");
    init = 1;
}

// work around dlsym depending on calloc
// we keep track of any callocs made before orig_calloc is available
// and short-circuit them in free() and realloc() to use the internal allocator
#define EARLY_SIZE 128
static void *early_alloc[EARLY_SIZE] = {0};
static int early_pos = 0;

void *malloc(size_t size) {
    if (! init) alloc_init();

    if (is_host())
        return dlmalloc(size);
    return orig_malloc(size);
}

void *realloc(void *ptr, size_t size) {
    if (! init) alloc_init();
    

    for (int i = 0; i < early_pos; i++) {
        if (early_alloc[i] == ptr) {
            void *new_ptr = dlrealloc(ptr, size);
            early_alloc[i] = new_ptr;
            return new_ptr;
        }
    }

    void *new_ptr;
    if (is_host()) {
        new_ptr = dlrealloc(ptr, size);
    } else {
        new_ptr = orig_realloc(ptr, size);
    }
    return new_ptr;
}

void free(void *ptr) {
    if (! init) alloc_init();

    for (int i = 0; i < early_pos; i++) {
        if (early_alloc[i] == ptr) {
            dlfree(ptr);
            early_alloc[i] = NULL;
            return;
        }
    }

    if (is_host()) {
        return dlfree(ptr);
    }
    orig_free(ptr);
}

// this is rough because dlsym depends on calloc already existing
void *calloc(size_t nelem, size_t elsize) {
    void *ptr;
    if (orig_calloc == NULL) {
        if (early_pos >= EARLY_SIZE) {
            fprintf(stderr, "Error: ran out of early calloc() space.\n");
            fflush(stderr);
            abort();
        }
        ptr = dlcalloc(nelem, elsize);
        early_alloc[early_pos++] = ptr;
    } else if (is_host()) {
        ptr = dlcalloc(nelem, elsize);
    } else {
        ptr = orig_calloc(nelem, elsize);
    }
    return ptr;
}

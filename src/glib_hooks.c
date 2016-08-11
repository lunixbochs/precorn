#define _GNU_SOURCE

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "glib_private.h"
#include "inject.h"
#include "malloc.h"

// we check is_host() so glib in the guest doesn't break. we only need to fix unicorn's allocator.
static bool is_host() {
    int bogus = 0;
    uint64_t sp = (uint64_t)&bogus;
    if (ctx.stack_base == 0 || (sp >= ctx.stack_base && sp < ctx.stack_base + ctx.stack_size))
        return true;
    return false;
}
static void *malloc_hook(size_t size) {
    if (is_host())
        return dlmalloc(size);
    return malloc(size);
}
static void *realloc_hook(void *ptr, size_t size) {
    if (is_host())
        return dlrealloc(ptr, size);
    return realloc(ptr, size);
}
static void free_hook(void *ptr) {
    if (is_host())
        return dlfree(ptr);
    return free(ptr);
}
static void *calloc_hook(size_t nelem, size_t elsize) {
    if (is_host())
        return dlcalloc(nelem, elsize);
    return calloc(nelem, elsize);
}
static GMemVTable glib_mman = {
    .malloc = malloc_hook,
    .realloc = realloc_hook,
    .free = free_hook,
    .calloc = calloc_hook,
    .try_malloc = NULL,
    .try_realloc = NULL,
};

void glib_memhook() {
    g_mem_set_vtable(&glib_mman);
}

char *g_strdup(char *s) {
    if (!s) return s;
    char *tmp = malloc_hook(strlen(s));
    strcpy(tmp, s);
    return tmp;
}

char *g_strdup_printf(char *fmt, ...) {
    char tmp[1025] = {0};
    va_list list;
    va_start(list, fmt);
    vsnprintf(tmp, 1024, fmt, list);
    va_end(list);
    return g_strdup(tmp);
}

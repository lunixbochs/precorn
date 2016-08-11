// from glib/gmem.h

typedef struct {
  void *(*malloc)  (size_t n_bytes);
  void *(*realloc) (void *mem, size_t n_bytes);
  void  (*free)    (void *mem);

  /* optional; set to NULL if not used ! */
  void *(*calloc)      (size_t n_blocks, size_t n_block_bytes);
  void *(*try_malloc)  (size_t n_bytes);
  void *(*try_realloc) (void *mem, size_t n_bytes);
} GMemVTable;

extern void g_mem_set_vtable(GMemVTable *vtable);

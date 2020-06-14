#ifndef SENTINEL_MEMORY_PROTECTION_H
#define SENTINEL_MEMORY_PROTECTION_H

#include "sentinel/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int sentinel_mem_protect(sentinel_handle_t process, sentinel_addr_t address,
                         usize size, sentinel_protection_t new_prot,
                         sentinel_protection_t* old_prot);

int sentinel_mem_query(sentinel_handle_t process, sentinel_addr_t address,
                       sentinel_region_t* region);

int sentinel_mem_enum_regions(sentinel_handle_t process,
                              sentinel_enum_callback_t callback, void* ctx);

int sentinel_mem_read(sentinel_handle_t process, sentinel_addr_t address,
                      void* buffer, usize size, usize* bytes_read);

int sentinel_mem_write(sentinel_handle_t process, sentinel_addr_t address,
                       const void* buffer, usize size, usize* bytes_written);

/* Temporarily remove page protection, write, then restore */
int sentinel_mem_write_protected(sentinel_handle_t process,
                                  sentinel_addr_t address,
                                  const void* buffer, usize size);

#ifdef __cplusplus
}
#endif
#endif

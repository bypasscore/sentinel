#ifndef SENTINEL_MEMORY_INTEGRITY_H
#define SENTINEL_MEMORY_INTEGRITY_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_integrity_entry {
    sentinel_addr_t address;
    usize size;
    u32 checksum;
    u32 current_checksum;
    bool is_modified;
} sentinel_integrity_entry_t;
typedef struct sentinel_integrity_ctx {
    sentinel_integrity_entry_t* entries;
    usize count;
    usize capacity;
} sentinel_integrity_ctx_t;
int sentinel_integrity_init(sentinel_integrity_ctx_t* ctx, usize capacity);
void sentinel_integrity_destroy(sentinel_integrity_ctx_t* ctx);
int sentinel_integrity_add_region(sentinel_integrity_ctx_t* ctx,
                                   sentinel_addr_t address, usize size);
int sentinel_integrity_add_module(sentinel_integrity_ctx_t* ctx, const char* module_name);
int sentinel_integrity_check(sentinel_integrity_ctx_t* ctx, u32* violations);
u32 sentinel_integrity_crc32(const u8* data, usize size);
#ifdef __cplusplus
}
#endif
#endif

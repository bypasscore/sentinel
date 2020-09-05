#ifndef SENTINEL_MEMORY_ALLOCATOR_H
#define SENTINEL_MEMORY_ALLOCATOR_H

#include "sentinel/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sentinel_alloc_strategy {
    SENTINEL_ALLOC_NORMAL = 0,
    SENTINEL_ALLOC_BETWEEN_MODULES,
    SENTINEL_ALLOC_NEAR_ADDRESS,
    SENTINEL_ALLOC_IN_SECTION_PADDING,
    SENTINEL_ALLOC_CODE_CAVE
} sentinel_alloc_strategy_t;

typedef struct sentinel_alloc_config {
    sentinel_alloc_strategy_t strategy;
    sentinel_addr_t           preferred_address;
    sentinel_addr_t           range_min;
    sentinel_addr_t           range_max;
    sentinel_protection_t     protection;
    bool                      zero_memory;
} sentinel_alloc_config_t;

sentinel_addr_t sentinel_alloc(sentinel_handle_t process, usize size,
                                const sentinel_alloc_config_t* config);
int sentinel_free(sentinel_handle_t process, sentinel_addr_t address, usize size);
sentinel_addr_t sentinel_find_code_cave(sentinel_handle_t process,
                                         const char* module_name,
                                         usize min_size);
sentinel_addr_t sentinel_alloc_near(sentinel_handle_t process,
                                     sentinel_addr_t target, usize size,
                                     sentinel_protection_t prot);

#ifdef __cplusplus
}
#endif
#endif

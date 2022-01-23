#ifndef SENTINEL_DRIVER_MAPPER_H
#define SENTINEL_DRIVER_MAPPER_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_mapper_config {
    bool resolve_imports;
    bool fix_relocations;
    bool call_entry_point;
    bool erase_headers;
    bool disable_exceptions;
} sentinel_mapper_config_t;
int sentinel_driver_map(const u8* driver_data, usize driver_size,
                         const sentinel_mapper_config_t* config,
                         sentinel_addr_t* mapped_base);
int sentinel_driver_map_file(const char* driver_path,
                              const sentinel_mapper_config_t* config,
                              sentinel_addr_t* mapped_base);
#ifdef __cplusplus
}
#endif
#endif

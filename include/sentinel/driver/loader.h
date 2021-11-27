#ifndef SENTINEL_DRIVER_LOADER_H
#define SENTINEL_DRIVER_LOADER_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_driver_info {
    char path[SENTINEL_MAX_PATH];
    char service_name[128];
    sentinel_addr_t image_base;
    u32 image_size;
    bool is_loaded;
} sentinel_driver_info_t;
int sentinel_driver_load(const char* driver_path, const char* service_name);
int sentinel_driver_unload(const char* service_name);
int sentinel_driver_register_service(const char* driver_path, const char* service_name);
int sentinel_driver_delete_service(const char* service_name);
bool sentinel_driver_is_loaded(const char* service_name);
#ifdef __cplusplus
}
#endif
#endif

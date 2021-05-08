#ifndef SENTINEL_PROCESS_HIDE_H
#define SENTINEL_PROCESS_HIDE_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum sentinel_hide_method {
    SENTINEL_HIDE_PEB_UNLINK = 0,
    SENTINEL_HIDE_DKOM,
    SENTINEL_HIDE_HOOK_ENUM
} sentinel_hide_method_t;
int sentinel_hide_module(sentinel_handle_t process, const char* module_name);
int sentinel_hide_module_from_peb(const char* module_name);
int sentinel_unlink_module_from_ldr(sentinel_addr_t ldr_entry);
int sentinel_spoof_module_name(const char* real_name, const char* fake_name);
int sentinel_erase_pe_headers(sentinel_handle_t process, sentinel_addr_t module_base);
#ifdef __cplusplus
}
#endif
#endif

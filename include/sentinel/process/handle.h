#ifndef SENTINEL_PROCESS_HANDLE_H
#define SENTINEL_PROCESS_HANDLE_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_handle_info {
    u32 handle_value;
    u32 pid;
    u16 object_type;
    u8 granted_access;
    char type_name[64];
    char object_name[SENTINEL_MAX_PATH];
} sentinel_handle_info_t;
int sentinel_enum_handles(sentinel_pid_t pid, sentinel_enum_callback_t cb, void* ctx);
int sentinel_close_remote_handle(sentinel_pid_t pid, u32 handle_value);
int sentinel_duplicate_handle(sentinel_pid_t source_pid, u32 source_handle,
                               sentinel_handle_t* out_handle);
int sentinel_strip_handle_access(sentinel_pid_t pid, u32 handle_value, u32 access_mask);
#ifdef __cplusplus
}
#endif
#endif

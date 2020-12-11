#ifndef SENTINEL_PROCESS_INJECTION_H
#define SENTINEL_PROCESS_INJECTION_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum sentinel_inject_method {
    SENTINEL_INJECT_LOADLIBRARY = 0,
    SENTINEL_INJECT_MANUAL_MAP,
    SENTINEL_INJECT_THREAD_HIJACK,
    SENTINEL_INJECT_APC_QUEUE
} sentinel_inject_method_t;
typedef struct sentinel_inject_config {
    sentinel_inject_method_t method;
    bool erase_pe_headers;
    bool unlink_module;
    u32 thread_creation_flags;
} sentinel_inject_config_t;
int sentinel_inject_dll(sentinel_pid_t target_pid, const char* dll_path, const sentinel_inject_config_t* config);
int sentinel_inject_shellcode(sentinel_pid_t target_pid, const u8* shellcode, usize size, sentinel_addr_t* entry_point);
int sentinel_inject_loadlibrary(sentinel_pid_t pid, const char* dll_path);
int sentinel_inject_manual_map(sentinel_pid_t pid, const u8* dll_data, usize dll_size);
int sentinel_inject_thread_hijack(sentinel_pid_t pid, const u8* shellcode, usize size);
#ifdef __cplusplus
}
#endif
#endif

#ifndef SENTINEL_PROCESS_HOLLOWING_H
#define SENTINEL_PROCESS_HOLLOWING_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_hollow_config {
    const char* target_path;
    const u8* payload_data;
    usize payload_size;
    bool create_suspended;
    u32 creation_flags;
} sentinel_hollow_config_t;
typedef struct sentinel_hollow_result {
    sentinel_pid_t pid;
    sentinel_tid_t tid;
    sentinel_addr_t image_base;
    sentinel_addr_t entry_point;
    sentinel_handle_t process_handle;
    sentinel_handle_t thread_handle;
} sentinel_hollow_result_t;
int sentinel_hollow_process(const sentinel_hollow_config_t* config, sentinel_hollow_result_t* result);
int sentinel_hollow_resume(sentinel_hollow_result_t* result);
#ifdef __cplusplus
}
#endif
#endif

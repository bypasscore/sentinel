#ifndef SENTINEL_DETECTION_ANALYZER_H
#define SENTINEL_DETECTION_ANALYZER_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum sentinel_ac_type {
    SENTINEL_AC_UNKNOWN = 0,
    SENTINEL_AC_EAC,
    SENTINEL_AC_BATTLEYE,
    SENTINEL_AC_VANGUARD,
    SENTINEL_AC_XIGNCODE,
    SENTINEL_AC_GAMEGUARD,
    SENTINEL_AC_VAC,
    SENTINEL_AC_FACEIT
} sentinel_ac_type_t;
typedef struct sentinel_ac_info {
    sentinel_ac_type_t type;
    char name[64];
    char version[32];
    sentinel_pid_t pid;
    char driver_name[128];
    bool kernel_module_loaded;
    bool user_module_loaded;
    bool is_ring0;
    u32 detection_capabilities;
} sentinel_ac_info_t;
#define SENTINEL_DETECT_MEMORY_SCAN    (1 << 0)
#define SENTINEL_DETECT_MODULE_ENUM    (1 << 1)
#define SENTINEL_DETECT_HANDLE_CHECK   (1 << 2)
#define SENTINEL_DETECT_DRIVER_CHECK   (1 << 3)
#define SENTINEL_DETECT_SYSCALL_HOOK   (1 << 4)
#define SENTINEL_DETECT_THREAD_CHECK   (1 << 5)
#define SENTINEL_DETECT_TIMING_CHECK   (1 << 6)
#define SENTINEL_DETECT_HYPERVISOR     (1 << 7)
#define SENTINEL_DETECT_DEBUG_CHECK    (1 << 8)
int sentinel_ac_detect(sentinel_ac_info_t* info);
int sentinel_ac_identify(sentinel_pid_t pid, sentinel_ac_info_t* info);
int sentinel_ac_enum_modules(sentinel_pid_t pid, sentinel_enum_callback_t cb, void* ctx);
int sentinel_ac_check_detection_vectors(const sentinel_ac_info_t* ac, u32* active_vectors);
#ifdef __cplusplus
}
#endif
#endif

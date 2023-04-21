#ifndef SENTINEL_DETECTION_SYSCALL_H
#define SENTINEL_DETECTION_SYSCALL_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_syscall_info {
    char function_name[128];
    sentinel_addr_t expected_address;
    sentinel_addr_t current_address;
    bool is_hooked;
    u8 original_bytes[16];
    u8 current_bytes[16];
} sentinel_syscall_info_t;
int sentinel_detect_syscall_hooks(sentinel_enum_callback_t cb, void* ctx);
int sentinel_check_ntdll_integrity(u32* num_hooks_found);
int sentinel_get_clean_syscall_stub(const char* function_name, u8* stub, usize stub_size);
bool sentinel_is_function_hooked(sentinel_addr_t function_address);
#ifdef __cplusplus
}
#endif
#endif

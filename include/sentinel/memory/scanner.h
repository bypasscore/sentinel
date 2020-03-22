#ifndef SENTINEL_MEMORY_SCANNER_H
#define SENTINEL_MEMORY_SCANNER_H

#include "sentinel/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentinel_scan_config {
    sentinel_pid_t      target_pid;
    sentinel_addr_t     start_address;
    sentinel_addr_t     end_address;
    bool                scan_executable;
    bool                scan_writable;
    bool                skip_guard_pages;
    u32                 alignment;
} sentinel_scan_config_t;

typedef struct sentinel_scan_result {
    sentinel_match_t*   matches;
    usize               count;
    usize               capacity;
} sentinel_scan_result_t;

int sentinel_scan_init_result(sentinel_scan_result_t* result, usize initial_capacity);
void sentinel_scan_free_result(sentinel_scan_result_t* result);
int sentinel_scan_pattern(sentinel_pid_t pid, const char* pattern,
                          const sentinel_scan_config_t* config,
                          sentinel_scan_result_t* result);
int sentinel_scan_bytes(const u8* haystack, usize haystack_size,
                        const u8* needle, usize needle_size,
                        const u8* mask, sentinel_scan_result_t* result);
int sentinel_parse_ida_pattern(const char* pattern, u8* bytes, u8* mask, usize* out_len);

#ifdef __cplusplus
}

namespace sentinel { namespace memory {
class Scanner {
public:
    Scanner();
    ~Scanner();
    void set_target(sentinel_pid_t pid);
    void set_range(sentinel_addr_t start, sentinel_addr_t end);
    void set_alignment(u32 alignment);
    int scan(const char* ida_pattern);
    usize match_count() const;
    const sentinel_match_t* matches() const;
    sentinel_addr_t first_match() const;
    void reset();
private:
    sentinel_scan_config_t config_;
    sentinel_scan_result_t result_;
};
}}
#endif
#endif

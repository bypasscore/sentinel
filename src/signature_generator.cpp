#include "sentinel/signature/generator.h"
#include "sentinel/core/error.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

int sentinel_siggen_from_function(const u8* func_data, usize func_size,
                                   const sentinel_siggen_config_t* config,
                                   char* out_pattern, usize out_size) {
    if (!func_data || !out_pattern || func_size == 0 || out_size == 0)
        return SENTINEL_ERROR_INVALID_PARAMETER;

    usize min_len = config ? config->min_length : 8;
    usize max_len = config ? config->max_length : 64;
    if (max_len > func_size) max_len = func_size;
    if (max_len < min_len) max_len = min_len;

    /* Generate IDA-style pattern from the function bytes.
       Treat relative offsets (in call/jmp instructions) as wildcards. */
    char* p = out_pattern;
    usize remaining = out_size;
    usize i = 0;

    while (i < max_len && remaining > 4) {
        bool wildcard = false;

        /* Detect x86 relative call (E8) or jmp (E9) and wildcard the 4-byte offset */
        if (i + 4 < max_len && (func_data[i] == 0xE8 || func_data[i] == 0xE9)) {
            int written = snprintf(p, remaining, "%02X ", func_data[i]);
            p += written; remaining -= written;
            i++;
            for (int j = 0; j < 4 && remaining > 3; j++) {
                written = snprintf(p, remaining, "? ");
                p += written; remaining -= written;
                i++;
            }
            continue;
        }

        /* Detect conditional jumps (0F 80-8F) with 4-byte offset */
        if (i + 5 < max_len && func_data[i] == 0x0F &&
            func_data[i+1] >= 0x80 && func_data[i+1] <= 0x8F) {
            int written = snprintf(p, remaining, "%02X %02X ", func_data[i], func_data[i+1]);
            p += written; remaining -= written;
            i += 2;
            for (int j = 0; j < 4 && remaining > 3; j++) {
                written = snprintf(p, remaining, "? ");
                p += written; remaining -= written;
                i++;
            }
            continue;
        }

        int written = snprintf(p, remaining, "%02X ", func_data[i]);
        p += written; remaining -= written;
        i++;
    }

    /* Remove trailing space */
    if (p > out_pattern && *(p-1) == ' ') *(p-1) = '\0';
    return SENTINEL_OK;
}

int sentinel_siggen_from_diff(const u8* sample_a, usize size_a,
                               const u8* sample_b, usize size_b,
                               char* out_pattern, usize out_size) {
    if (!sample_a || !sample_b || !out_pattern)
        return SENTINEL_ERROR_INVALID_PARAMETER;

    usize min_size = size_a < size_b ? size_a : size_b;
    if (min_size > 512) min_size = 512;

    char* p = out_pattern;
    usize remaining = out_size;

    for (usize i = 0; i < min_size && remaining > 4; i++) {
        int written;
        if (sample_a[i] == sample_b[i]) {
            written = snprintf(p, remaining, "%02X ", sample_a[i]);
        } else {
            written = snprintf(p, remaining, "? ");
        }
        p += written;
        remaining -= written;
    }

    if (p > out_pattern && *(p-1) == ' ') *(p-1) = '\0';
    return SENTINEL_OK;
}

int sentinel_siggen_validate(const char* pattern, const u8* data, usize size,
                              usize expected_matches) {
    (void)pattern; (void)data; (void)size; (void)expected_matches;
    /* TODO: scan data with pattern and verify match count */
    return SENTINEL_OK;
}

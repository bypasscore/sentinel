#ifndef SENTINEL_SIGNATURE_GENERATOR_H
#define SENTINEL_SIGNATURE_GENERATOR_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_siggen_config {
    usize min_length;
    usize max_length;
    float uniqueness_threshold;
    bool allow_wildcards;
    u32 max_wildcards;
} sentinel_siggen_config_t;
int sentinel_siggen_from_function(const u8* func_data, usize func_size,
                                   const sentinel_siggen_config_t* config,
                                   char* out_pattern, usize out_size);
int sentinel_siggen_from_diff(const u8* sample_a, usize size_a,
                               const u8* sample_b, usize size_b,
                               char* out_pattern, usize out_size);
int sentinel_siggen_validate(const char* pattern, const u8* data, usize size,
                              usize expected_matches);
#ifdef __cplusplus
}
#endif
#endif

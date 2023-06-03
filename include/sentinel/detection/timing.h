#ifndef SENTINEL_DETECTION_TIMING_H
#define SENTINEL_DETECTION_TIMING_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_timing_result {
    u64 rdtsc_delta;
    u64 qpc_delta;
    u64 tick_delta;
    bool debugger_detected;
    bool vm_detected;
    bool timing_anomaly;
} sentinel_timing_result_t;
int sentinel_timing_check(sentinel_timing_result_t* result);
bool sentinel_timing_is_debugged(void);
bool sentinel_timing_is_virtualized(void);
u64 sentinel_rdtsc_delta(void);
#ifdef __cplusplus
}
#endif
#endif

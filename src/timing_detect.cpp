#include "sentinel/detection/timing.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>

u64 sentinel_rdtsc_delta(void) {
    u64 start = __rdtsc();
    /* Execute some trivial operations */
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    u64 end = __rdtsc();
    return end - start;
}

bool sentinel_timing_is_debugged(void) {
    /* RDTSC-based debugger detection:
       Under a debugger, single-stepping causes huge RDTSC deltas */
    u64 delta = sentinel_rdtsc_delta();
    /* Normal execution: ~200-2000 cycles. Debugger: >100000 */
    return (delta > 50000);
}

bool sentinel_timing_is_virtualized(void) {
    /* VM exit on CPUID causes measurable overhead */
    u64 start = __rdtsc();
    int info[4];
    __cpuid(info, 0);
    u64 end = __rdtsc();
    u64 delta = end - start;
    /* Native: ~100-300 cycles. VM: >1000 */
    return (delta > 1500);
}

int sentinel_timing_check(sentinel_timing_result_t* result) {
    if (!result) return SENTINEL_ERROR_INVALID_PARAMETER;
    memset(result, 0, sizeof(*result));

    /* RDTSC measurement */
    result->rdtsc_delta = sentinel_rdtsc_delta();

    /* QPC measurement */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    volatile int d = 0;
    for (int i = 0; i < 1000; i++) d += i;
    QueryPerformanceCounter(&end);
    result->qpc_delta = (u64)(end.QuadPart - start.QuadPart);

    /* GetTickCount measurement */
    DWORD tick_start = GetTickCount();
    Sleep(1);
    DWORD tick_end = GetTickCount();
    result->tick_delta = (u64)(tick_end - tick_start);

    /* Analyze results */
    result->debugger_detected = (result->rdtsc_delta > 50000);
    result->vm_detected = sentinel_timing_is_virtualized();
    result->timing_anomaly = (result->tick_delta > 100) || (result->rdtsc_delta > 100000);

    if (result->debugger_detected)
        SLOG_WARN("Timing analysis: possible debugger (RDTSC delta: %llu)", result->rdtsc_delta);
    if (result->vm_detected)
        SLOG_INFO("Timing analysis: hypervisor detected");

    return SENTINEL_OK;
}

#else
u64 sentinel_rdtsc_delta(void) { return 0; }
bool sentinel_timing_is_debugged(void) { return false; }
bool sentinel_timing_is_virtualized(void) { return false; }
int sentinel_timing_check(sentinel_timing_result_t* r) { (void)r; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

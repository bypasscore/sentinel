/*
 * ac_probe.cpp -- Anti-cheat detection probe tool
 *
 * Identifies running anti-cheat systems and their detection capabilities.
 */

#include "sentinel/sentinel.h"
#include "sentinel/detection/analyzer.h"
#include "sentinel/detection/syscall.h"
#include "sentinel/detection/timing.h"
#include "sentinel/utils/logger.h"
#include <cstdio>
#include <cstring>

static const char* ac_type_name(sentinel_ac_type_t type) {
    switch (type) {
        case SENTINEL_AC_EAC: return "Easy Anti-Cheat";
        case SENTINEL_AC_BATTLEYE: return "BattlEye";
        case SENTINEL_AC_VANGUARD: return "Riot Vanguard";
        case SENTINEL_AC_XIGNCODE: return "XIGNCODE3";
        case SENTINEL_AC_GAMEGUARD: return "nProtect GameGuard";
        case SENTINEL_AC_VAC: return "Valve Anti-Cheat";
        case SENTINEL_AC_FACEIT: return "FACEIT Anti-Cheat";
        default: return "Unknown";
    }
}

static bool on_hook(const void* data, void* ctx) {
    const sentinel_syscall_info_t* info = (const sentinel_syscall_info_t*)data;
    u32* count = (u32*)ctx;
    if (info->is_hooked) {
        (*count)++;
        printf("  [HOOKED] %s at %p\n", info->function_name, (void*)info->current_address);
        printf("           Bytes: ");
        for (int i = 0; i < 8; i++) printf("%02X ", info->current_bytes[i]);
        printf("\n");
    }
    return true;
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    sentinel_init();
    sentinel_log_init(SENTINEL_LOG_WARN);

    printf("=== Sentinel Anti-Cheat Probe v%s ===\n\n", SENTINEL_VERSION_STRING);

    /* Check privileges */
    printf("[*] Privilege check: %s\n\n",
           sentinel_is_elevated() ? "ELEVATED" : "NOT ELEVATED (some checks may fail)");

    /* Detect anti-cheat */
    printf("[*] Scanning for anti-cheat systems...\n");
    sentinel_ac_info_t ac = {};
    int rc = sentinel_ac_detect(&ac);
    if (rc == SENTINEL_OK) {
        printf("  Detected: %s (%s)\n", ac.name, ac_type_name(ac.type));
        printf("  PID: %u\n", ac.pid);
        printf("  Kernel driver: %s (%s)\n",
               ac.kernel_module_loaded ? "YES" : "NO",
               ac.driver_name[0] ? ac.driver_name : "N/A");
        printf("  Ring-0: %s\n\n", ac.is_ring0 ? "YES" : "NO");

        u32 vectors = 0;
        sentinel_ac_check_detection_vectors(&ac, &vectors);
        printf("  Detection vectors:\n");
        if (vectors & SENTINEL_DETECT_MEMORY_SCAN)  printf("    - Memory scanning\n");
        if (vectors & SENTINEL_DETECT_MODULE_ENUM)   printf("    - Module enumeration\n");
        if (vectors & SENTINEL_DETECT_HANDLE_CHECK)  printf("    - Handle validation\n");
        if (vectors & SENTINEL_DETECT_DRIVER_CHECK)  printf("    - Driver integrity\n");
        if (vectors & SENTINEL_DETECT_SYSCALL_HOOK)  printf("    - Syscall monitoring\n");
        if (vectors & SENTINEL_DETECT_THREAD_CHECK)  printf("    - Thread inspection\n");
        if (vectors & SENTINEL_DETECT_TIMING_CHECK)  printf("    - Timing analysis\n");
        if (vectors & SENTINEL_DETECT_HYPERVISOR)    printf("    - Hypervisor-based\n");
        if (vectors & SENTINEL_DETECT_DEBUG_CHECK)   printf("    - Debug detection\n");
    } else {
        printf("  No known anti-cheat detected.\n");
    }

    /* Syscall hook detection */
    printf("\n[*] Checking syscall hooks...\n");
    u32 hook_count = 0;
    sentinel_detect_syscall_hooks(on_hook, &hook_count);
    if (hook_count == 0) printf("  No syscall hooks detected.\n");
    else printf("  Total hooks: %u\n", hook_count);

    /* ntdll integrity */
    printf("\n[*] ntdll.dll integrity check...\n");
    u32 patches = 0;
    sentinel_check_ntdll_integrity(&patches);
    printf("  Patches/modifications found: %u\n", patches);

    /* Timing checks */
    printf("\n[*] Timing analysis...\n");
    sentinel_timing_result_t timing = {};
    sentinel_timing_check(&timing);
    printf("  RDTSC delta: %llu cycles\n", (unsigned long long)timing.rdtsc_delta);
    printf("  Debugger: %s\n", timing.debugger_detected ? "LIKELY" : "not detected");
    printf("  Hypervisor: %s\n", timing.vm_detected ? "DETECTED" : "not detected");

    /* Platform info */
    printf("\n[*] Platform info:\n");
    sentinel_os_version_t ver = {};
    sentinel_get_os_version(&ver);
    printf("  Windows %u.%u.%u\n", ver.major, ver.minor, ver.build);
    printf("  Secure Boot: %s\n", sentinel_is_secure_boot() ? "YES" : "NO");
    printf("  VBS/HVCI: %s\n", sentinel_is_vbs_enabled() ? "ENABLED" : "disabled");
    printf("  Hypervisor: %s\n", sentinel_is_hypervisor_present() ? "YES" : "NO");

    printf("\n=== Probe complete ===\n");

    sentinel_shutdown();
    return 0;
}

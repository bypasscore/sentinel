/*
 * basic_scan.cpp -- Basic memory scanning example
 *
 * Demonstrates how to use the pattern scanner to find
 * specific byte sequences in a target process.
 */

#include "sentinel/sentinel.h"
#include "sentinel/memory/scanner.h"
#include "sentinel/utils/pe_parser.h"
#include "sentinel/utils/logger.h"
#include <cstdio>

int main() {
    sentinel_init();
    sentinel_log_init(SENTINEL_LOG_DEBUG);

    printf("Sentinel Basic Scan Example\n");
    printf("===========================\n\n");

    /* Example 1: Scan a file for a pattern */
    const char* target = "C:\Windows\System32\ntdll.dll";
    printf("[1] Scanning %s for NtReadVirtualMemory prologue...\n", target);

    sentinel_pe_info_t pe = {};
    if (sentinel_pe_parse_file(target, &pe) == SENTINEL_OK) {
        printf("    PE Info: %s, %u sections, entry RVA 0x%X\n",
               pe.is_64bit ? "x64" : "x86", pe.num_sections, pe.entry_point_rva);

        for (u32 i = 0; i < pe.num_sections && i < 5; i++) {
            printf("    Section: %.8s  VA: 0x%08X  Size: 0x%X\n",
                   pe.sections[i].name, pe.sections[i].virtual_address,
                   pe.sections[i].virtual_size);
        }
    }

    /* Example 2: In-memory pattern scan */
    printf("\n[2] In-memory pattern scan demo...\n");

    /* Create a test buffer with a known pattern */
    u8 test_data[] = {
        0x90, 0x90, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57,
        0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90,
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83,
        0xEC, 0x30, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
    };

    /* IDA-style pattern: 48 89 5C 24 ? 57 48 83 EC ? */
    const char* pattern = "48 89 5C 24 ? 57 48 83 EC ?";
    printf("    Pattern: %s\n", pattern);

    u8 bytes[SENTINEL_MAX_PATTERN_LEN], mask[SENTINEL_MAX_PATTERN_LEN];
    usize pat_len = 0;
    sentinel_parse_ida_pattern(pattern, bytes, mask, &pat_len);

    sentinel_scan_result_t result = {};
    sentinel_scan_init_result(&result, 32);
    sentinel_scan_bytes(test_data, sizeof(test_data), bytes, pat_len, mask, &result);

    printf("    Found %zu matches:\n", result.count);
    for (usize i = 0; i < result.count; i++) {
        printf("      [%zu] Offset: 0x%zX\n", i, result.matches[i].offset);
    }

    sentinel_scan_free_result(&result);

    printf("\nDone.\n");
    sentinel_shutdown();
    return 0;
}

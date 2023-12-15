/*
 * sig_scan.cpp -- Standalone signature scanner tool
 *
 * Usage: sig_scan <signature_db> <target_file>
 *        sig_scan --pattern "48 8B ?? ?? ?? ?? ?? 48 85 C0" <target_file>
 */

#include "sentinel/sentinel.h"
#include "sentinel/signature/scanner.h"
#include "sentinel/memory/scanner.h"
#include "sentinel/utils/pe_parser.h"
#include "sentinel/utils/logger.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static bool on_match(const void* data, void* ctx) {
    const sentinel_match_t* m = (const sentinel_match_t*)data;
    u32* count = (u32*)ctx;
    (*count)++;
    printf("  [%u] Match at offset 0x%llX (address %p)\n",
           *count, (unsigned long long)m->offset, (void*)m->address);
    return true;
}

static void print_usage(const char* prog) {
    printf("Sentinel Signature Scanner v%s\n\n", SENTINEL_VERSION_STRING);
    printf("Usage:\n");
    printf("  %s <signature_db> <target_file>\n", prog);
    printf("  %s --pattern <ida_pattern> <target_file>\n", prog);
    printf("\nExamples:\n");
    printf("  %s sigs.db game.exe\n", prog);
    printf("  %s --pattern \"48 89 5C 24 ? 57 48 83 EC 20\" ntdll.dll\n", prog);
}

int main(int argc, char* argv[]) {
    sentinel_init();
    sentinel_log_init(SENTINEL_LOG_INFO);

    if (argc < 3) { print_usage(argv[0]); return 1; }

    if (strcmp(argv[1], "--pattern") == 0 && argc >= 4) {
        const char* pattern = argv[2];
        const char* target = argv[3];

        printf("Scanning %s for pattern: %s\n\n", target, pattern);

        FILE* f = fopen(target, "rb");
        if (!f) { fprintf(stderr, "Error: cannot open %s\n", target); return 1; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        u8* data = (u8*)malloc(sz);
        fread(data, 1, sz, f);
        fclose(f);

        /* Parse pattern */
        u8 bytes[SENTINEL_MAX_PATTERN_LEN], mask[SENTINEL_MAX_PATTERN_LEN];
        usize pat_len = 0;
        sentinel_parse_ida_pattern(pattern, bytes, mask, &pat_len);

        sentinel_scan_result_t result = {};
        sentinel_scan_init_result(&result, 128);
        sentinel_scan_bytes(data, sz, bytes, pat_len, mask, &result);

        printf("Found %zu match(es):\n", result.count);
        for (usize i = 0; i < result.count; i++) {
            printf("  [%zu] Offset: 0x%llX\n", i+1,
                   (unsigned long long)result.matches[i].offset);
        }

        sentinel_scan_free_result(&result);
        free(data);
    } else {
        const char* db_path = argv[1];
        const char* target = argv[2];

        sentinel_sig_database_t db = {};
        sentinel_sig_db_create(&db, 256);

        if (sentinel_sig_db_load_file(&db, db_path) != SENTINEL_OK) {
            fprintf(stderr, "Error: cannot load signature database %s\n", db_path);
            return 1;
        }

        printf("Loaded %zu signatures from %s\n", db.count, db_path);
        printf("Scanning %s...\n\n", target);

        u32 match_count = 0;
        sentinel_sig_scan_file(&db, target, on_match, &match_count);

        printf("\nTotal matches: %u\n", match_count);
        sentinel_sig_db_destroy(&db);
    }

    sentinel_shutdown();
    return 0;
}

#include "sentinel/signature/scanner.h"
#include "sentinel/memory/scanner.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

int sentinel_sig_db_create(sentinel_sig_database_t* db, usize cap) {
    if (!db) return SENTINEL_ERROR_INVALID_PARAMETER;
    db->entries = (sentinel_sig_entry_t*)calloc(cap, sizeof(sentinel_sig_entry_t));
    if (!db->entries) return SENTINEL_ERROR_OUT_OF_MEMORY;
    db->count = 0;
    db->capacity = cap;
    return SENTINEL_OK;
}

void sentinel_sig_db_destroy(sentinel_sig_database_t* db) {
    if (db && db->entries) { free(db->entries); db->entries = nullptr; db->count = 0; }
}

int sentinel_sig_db_add(sentinel_sig_database_t* db, const char* name, const char* pattern) {
    if (!db || !name || !pattern) return SENTINEL_ERROR_INVALID_PARAMETER;
    if (db->count >= db->capacity) {
        usize nc = db->capacity * 2;
        sentinel_sig_entry_t* ne = (sentinel_sig_entry_t*)realloc(db->entries, nc * sizeof(sentinel_sig_entry_t));
        if (!ne) return SENTINEL_ERROR_OUT_OF_MEMORY;
        db->entries = ne;
        db->capacity = nc;
    }
    sentinel_sig_entry_t* e = &db->entries[db->count];
    memset(e, 0, sizeof(*e));
    strncpy(e->name, name, sizeof(e->name) - 1);
    strncpy(e->pattern, pattern, sizeof(e->pattern) - 1);
    e->min_confidence = 1.0f;
    db->count++;
    return SENTINEL_OK;
}

int sentinel_sig_db_load_file(sentinel_sig_database_t* db, const char* filepath) {
    if (!db || !filepath) return SENTINEL_ERROR_INVALID_PARAMETER;
    FILE* f = fopen(filepath, "r");
    if (!f) return SENTINEL_ERROR_IO;
    char line[4352];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char name[128], pattern[SENTINEL_MAX_SIGNATURE];
        if (sscanf(line, "%127[^=]=%4095s", name, pattern) == 2) {
            sentinel_sig_db_add(db, name, pattern);
        }
    }
    fclose(f);
    return SENTINEL_OK;
}

int sentinel_sig_db_save_file(const sentinel_sig_database_t* db, const char* filepath) {
    if (!db || !filepath) return SENTINEL_ERROR_INVALID_PARAMETER;
    FILE* f = fopen(filepath, "w");
    if (!f) return SENTINEL_ERROR_IO;
    fprintf(f, "# Sentinel signature database\n");
    for (usize i = 0; i < db->count; i++)
        fprintf(f, "%s=%s\n", db->entries[i].name, db->entries[i].pattern);
    fclose(f);
    return SENTINEL_OK;
}

typedef struct { const sentinel_sig_entry_t* sig; sentinel_enum_callback_t cb; void* ctx; } scan_ctx_t;

int sentinel_sig_scan_buffer(const sentinel_sig_database_t* db, const u8* data, usize size,
                             sentinel_enum_callback_t cb, void* ctx) {
    if (!db || !data || !cb) return SENTINEL_ERROR_INVALID_PARAMETER;
    for (usize s = 0; s < db->count; s++) {
        u8 bytes[SENTINEL_MAX_PATTERN_LEN], mask[SENTINEL_MAX_PATTERN_LEN];
        usize pat_len = 0;
        sentinel_parse_ida_pattern(db->entries[s].pattern, bytes, mask, &pat_len);
        if (pat_len == 0) continue;
        for (usize i = 0; i + pat_len <= size; i++) {
            bool match = true;
            for (usize j = 0; j < pat_len; j++) {
                if ((data[i+j] & mask[j]) != (bytes[j] & mask[j])) { match = false; break; }
            }
            if (match) {
                sentinel_match_t m = {};
                m.address = (sentinel_addr_t)(data + i);
                m.offset = i;
                m.confidence = 1.0f;
                if (!cb(&m, ctx)) return SENTINEL_OK;
            }
        }
    }
    return SENTINEL_OK;
}

int sentinel_sig_scan_file(const sentinel_sig_database_t* db, const char* filepath,
                           sentinel_enum_callback_t cb, void* ctx) {
    if (!filepath) return SENTINEL_ERROR_INVALID_PARAMETER;
    FILE* f = fopen(filepath, "rb");
    if (!f) return SENTINEL_ERROR_IO;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* buf = (u8*)malloc(sz);
    if (!buf) { fclose(f); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    fread(buf, 1, sz, f);
    fclose(f);
    int rc = sentinel_sig_scan_buffer(db, buf, sz, cb, ctx);
    free(buf);
    return rc;
}

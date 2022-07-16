#ifndef SENTINEL_SIGNATURE_SCANNER_H
#define SENTINEL_SIGNATURE_SCANNER_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sentinel_sig_entry {
    char name[128];
    char pattern[SENTINEL_MAX_SIGNATURE];
    u32 flags;
    float min_confidence;
} sentinel_sig_entry_t;
typedef struct sentinel_sig_database {
    sentinel_sig_entry_t* entries;
    usize count;
    usize capacity;
} sentinel_sig_database_t;
int sentinel_sig_db_create(sentinel_sig_database_t* db, usize initial_capacity);
void sentinel_sig_db_destroy(sentinel_sig_database_t* db);
int sentinel_sig_db_add(sentinel_sig_database_t* db, const char* name, const char* pattern);
int sentinel_sig_db_load_file(sentinel_sig_database_t* db, const char* filepath);
int sentinel_sig_db_save_file(const sentinel_sig_database_t* db, const char* filepath);
int sentinel_sig_scan_file(const sentinel_sig_database_t* db, const char* filepath,
                           sentinel_enum_callback_t cb, void* ctx);
int sentinel_sig_scan_buffer(const sentinel_sig_database_t* db, const u8* data, usize size,
                             sentinel_enum_callback_t cb, void* ctx);
#ifdef __cplusplus
}
#endif
#endif

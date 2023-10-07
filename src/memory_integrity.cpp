#include "sentinel/memory/integrity.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdlib>

/* CRC32 lookup table */
static u32 crc32_table[256];
static bool crc32_initialized = false;

static void init_crc32_table(void) {
    for (u32 i = 0; i < 256; i++) {
        u32 crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = true;
}

u32 sentinel_integrity_crc32(const u8* data, usize size) {
    if (!crc32_initialized) init_crc32_table();
    u32 crc = 0xFFFFFFFF;
    for (usize i = 0; i < size; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

int sentinel_integrity_init(sentinel_integrity_ctx_t* ctx, usize capacity) {
    if (!ctx) return SENTINEL_ERROR_INVALID_PARAMETER;
    ctx->entries = (sentinel_integrity_entry_t*)calloc(capacity, sizeof(sentinel_integrity_entry_t));
    if (!ctx->entries) return SENTINEL_ERROR_OUT_OF_MEMORY;
    ctx->count = 0;
    ctx->capacity = capacity;
    return SENTINEL_OK;
}

void sentinel_integrity_destroy(sentinel_integrity_ctx_t* ctx) {
    if (ctx && ctx->entries) { free(ctx->entries); ctx->entries = nullptr; ctx->count = 0; }
}

int sentinel_integrity_add_region(sentinel_integrity_ctx_t* ctx,
                                   sentinel_addr_t address, usize size) {
    if (!ctx || !address || size == 0) return SENTINEL_ERROR_INVALID_PARAMETER;
    if (ctx->count >= ctx->capacity) return SENTINEL_ERROR_BUFFER_TOO_SMALL;

    sentinel_integrity_entry_t* e = &ctx->entries[ctx->count];
    e->address = address;
    e->size = size;
    e->checksum = sentinel_integrity_crc32((const u8*)address, size);
    e->current_checksum = e->checksum;
    e->is_modified = false;
    ctx->count++;
    return SENTINEL_OK;
}

int sentinel_integrity_add_module(sentinel_integrity_ctx_t* ctx, const char* module_name) {
#ifdef _WIN32
    HMODULE hmod = GetModuleHandleA(module_name);
    if (!hmod) return SENTINEL_ERROR_MODULE_NOT_FOUND;

    /* Add .text section for integrity monitoring */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hmod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((u8*)hmod + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            sentinel_addr_t addr = (sentinel_addr_t)hmod + sec[i].VirtualAddress;
            usize size = sec[i].Misc.VirtualSize;
            sentinel_integrity_add_region(ctx, addr, size);
            SLOG_INFO("Monitoring %s section %.8s at %p (%zu bytes)",
                      module_name, sec[i].Name, (void*)addr, size);
        }
    }
    return SENTINEL_OK;
#else
    (void)ctx; (void)module_name;
    return SENTINEL_ERROR_UNSUPPORTED;
#endif
}

int sentinel_integrity_check(sentinel_integrity_ctx_t* ctx, u32* violations) {
    if (!ctx || !violations) return SENTINEL_ERROR_INVALID_PARAMETER;
    *violations = 0;

    for (usize i = 0; i < ctx->count; i++) {
        sentinel_integrity_entry_t* e = &ctx->entries[i];
        e->current_checksum = sentinel_integrity_crc32((const u8*)e->address, e->size);
        e->is_modified = (e->current_checksum != e->checksum);
        if (e->is_modified) {
            (*violations)++;
            SLOG_WARN("Integrity violation at %p (expected CRC 0x%08X, got 0x%08X)",
                      (void*)e->address, e->checksum, e->current_checksum);
        }
    }
    return SENTINEL_OK;
}

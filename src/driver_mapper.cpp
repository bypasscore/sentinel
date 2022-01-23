#include "sentinel/driver/mapper.h"
#include "sentinel/utils/pe_parser.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING);

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH     1
#define IMAGE_REL_BASED_LOW      2
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_DIR64    10

typedef struct _RELOC_BLOCK {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} RELOC_BLOCK;

static int process_relocations(u8* mapped_image, sentinel_addr_t new_base,
                                sentinel_addr_t old_base, const sentinel_pe_info_t* pe,
                                const u8* original) {
    i64 delta = (i64)(new_base - old_base);
    if (delta == 0) return SENTINEL_OK;

    /* Find .reloc section or use data directory */
    const u8* coff = original + ((const sentinel_dos_header_t*)original)->e_lfanew + 4;
    const u8* opt = coff + 20;
    u16 magic = *(const u16*)opt;

    u32 reloc_rva = 0, reloc_size = 0;
    if (magic == 0x20B) { /* PE64 */
        reloc_rva  = *(const u32*)(opt + 152);
        reloc_size = *(const u32*)(opt + 156);
    } else {
        reloc_rva  = *(const u32*)(opt + 136);
        reloc_size = *(const u32*)(opt + 140);
    }

    if (reloc_rva == 0 || reloc_size == 0) return SENTINEL_OK;

    u32 reloc_off = sentinel_pe_rva_to_offset(pe, reloc_rva);
    if (reloc_off == 0) return SENTINEL_OK;

    const u8* reloc = mapped_image + reloc_rva;
    const u8* reloc_end = reloc + reloc_size;

    while (reloc < reloc_end) {
        const RELOC_BLOCK* block = (const RELOC_BLOCK*)reloc;
        if (block->SizeOfBlock == 0) break;

        u32 num_entries = (block->SizeOfBlock - sizeof(RELOC_BLOCK)) / sizeof(u16);
        const u16* entries = (const u16*)(reloc + sizeof(RELOC_BLOCK));

        for (u32 i = 0; i < num_entries; i++) {
            u16 type = entries[i] >> 12;
            u16 offset = entries[i] & 0xFFF;
            u8* target = mapped_image + block->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_DIR64:
                    *(u64*)target += (u64)delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(u32*)target += (u32)delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    SLOG_WARN("Unknown relocation type: %u", type);
                    break;
            }
        }
        reloc += block->SizeOfBlock;
    }
    return SENTINEL_OK;
}

int sentinel_driver_map(const u8* driver_data, usize driver_size,
                         const sentinel_mapper_config_t* config,
                         sentinel_addr_t* mapped_base) {
    if (!driver_data || driver_size == 0 || !mapped_base)
        return SENTINEL_ERROR_INVALID_PARAMETER;

    sentinel_pe_info_t pe = {};
    int rc = sentinel_pe_parse(driver_data, driver_size, &pe);
    if (rc != SENTINEL_OK) return rc;

    if (!pe.is_driver)
        SLOG_WARN("PE does not appear to be a native/driver subsystem binary");

    /* Allocate image buffer */
    u8* image = (u8*)VirtualAlloc(nullptr, pe.image_size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!image) return SENTINEL_ERROR_OUT_OF_MEMORY;

    /* Copy headers */
    memcpy(image, driver_data, pe.sections[0].raw_offset);

    /* Copy sections */
    for (u32 i = 0; i < pe.num_sections && i < 96; i++) {
        if (pe.sections[i].raw_size > 0 &&
            pe.sections[i].raw_offset + pe.sections[i].raw_size <= driver_size) {
            memcpy(image + pe.sections[i].virtual_address,
                   driver_data + pe.sections[i].raw_offset,
                   pe.sections[i].raw_size);
        }
    }

    /* Process relocations */
    if (!config || config->fix_relocations) {
        process_relocations(image, (sentinel_addr_t)image, pe.image_base,
                            &pe, driver_data);
    }

    /* Erase PE headers if requested */
    if (config && config->erase_headers) {
        memset(image, 0, pe.sections[0].virtual_address);
    }

    *mapped_base = (sentinel_addr_t)image;
    SLOG_INFO("Driver mapped at %p (size: 0x%X)", image, pe.image_size);
    return SENTINEL_OK;
}

int sentinel_driver_map_file(const char* driver_path,
                              const sentinel_mapper_config_t* config,
                              sentinel_addr_t* mapped_base) {
    if (!driver_path || !mapped_base) return SENTINEL_ERROR_INVALID_PARAMETER;
    FILE* f = fopen(driver_path, "rb");
    if (!f) return SENTINEL_ERROR_IO;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* buf = (u8*)malloc(sz);
    if (!buf) { fclose(f); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    fread(buf, 1, sz, f);
    fclose(f);
    int rc = sentinel_driver_map(buf, sz, config, mapped_base);
    free(buf);
    return rc;
}

#else
int sentinel_driver_map(const u8* d, usize s, const sentinel_mapper_config_t* c, sentinel_addr_t* b) { (void)d;(void)s;(void)c;(void)b; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_driver_map_file(const char* p, const sentinel_mapper_config_t* c, sentinel_addr_t* b) { (void)p;(void)c;(void)b; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

#include "sentinel/utils/pe_parser.h"
#include "sentinel/core/error.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

#define PE_DOS_MAGIC    0x5A4D
#define PE_NT_MAGIC     0x00004550
#define PE_OPT32_MAGIC  0x10B
#define PE_OPT64_MAGIC  0x20B
#define PE_SUBSYSTEM_NATIVE 1

bool sentinel_pe_is_valid(const u8* data, usize size) {
    if (!data || size < sizeof(sentinel_dos_header_t)) return false;
    const sentinel_dos_header_t* dos = (const sentinel_dos_header_t*)data;
    if (dos->e_magic != PE_DOS_MAGIC) return false;
    if ((u32)dos->e_lfanew + 4 > size) return false;
    u32 sig = *(const u32*)(data + dos->e_lfanew);
    return sig == PE_NT_MAGIC;
}

int sentinel_pe_parse(const u8* data, usize size, sentinel_pe_info_t* info) {
    if (!data || !info) return SENTINEL_ERROR_INVALID_PARAMETER;
    memset(info, 0, sizeof(*info));
    if (size < sizeof(sentinel_dos_header_t))
        return SENTINEL_ERROR_BUFFER_TOO_SMALL;
    const sentinel_dos_header_t* dos = (const sentinel_dos_header_t*)data;
    if (dos->e_magic != PE_DOS_MAGIC) return SENTINEL_ERROR_SIGNATURE_MISMATCH;
    u32 pe_off = (u32)dos->e_lfanew;
    if (pe_off + 24 > size) return SENTINEL_ERROR_BUFFER_TOO_SMALL;
    if (*(const u32*)(data + pe_off) != PE_NT_MAGIC) return SENTINEL_ERROR_SIGNATURE_MISMATCH;
    const u8* coff = data + pe_off + 4;
    info->machine = *(const u16*)coff;
    info->num_sections = *(const u16*)(coff + 2);
    info->timestamp = *(const u32*)(coff + 4);
    u16 opt_sz = *(const u16*)(coff + 16);
    u16 chars = *(const u16*)(coff + 18);
    info->is_dll = (chars & 0x2000) != 0;
    const u8* opt = coff + 20;
    u16 mag = *(const u16*)opt;
    if (mag == PE_OPT64_MAGIC) {
        info->is_64bit = true;
        info->entry_point_rva = *(const u32*)(opt+16);
        info->image_base = *(const u64*)(opt+24);
        info->image_size = *(const u32*)(opt+56);
        info->checksum = *(const u32*)(opt+64);
        info->subsystem = *(const u16*)(opt+68);
        info->dll_characteristics = *(const u16*)(opt+70);
    } else if (mag == PE_OPT32_MAGIC) {
        info->is_64bit = false;
        info->entry_point_rva = *(const u32*)(opt+16);
        info->image_base = *(const u32*)(opt+28);
        info->image_size = *(const u32*)(opt+56);
        info->checksum = *(const u32*)(opt+64);
        info->subsystem = *(const u16*)(opt+68);
        info->dll_characteristics = *(const u16*)(opt+70);
    } else return SENTINEL_ERROR_SIGNATURE_MISMATCH;
    info->is_driver = (info->subsystem == PE_SUBSYSTEM_NATIVE);
    const u8* sec = coff + 20 + opt_sz;
    u32 n = info->num_sections < 96 ? info->num_sections : 96;
    for (u32 i = 0; i < n; i++) {
        const u8* s = sec + i*40;
        if (s+40 > data+size) break;
        memcpy(info->sections[i].name, s, 8);
        info->sections[i].virtual_size = *(const u32*)(s+8);
        info->sections[i].virtual_address = *(const u32*)(s+12);
        info->sections[i].raw_size = *(const u32*)(s+16);
        info->sections[i].raw_offset = *(const u32*)(s+20);
        info->sections[i].characteristics = *(const u32*)(s+36);
    }
    info->is_valid = true;
    return SENTINEL_OK;
}

int sentinel_pe_parse_file(const char* filepath, sentinel_pe_info_t* info) {
    if (!filepath || !info) return SENTINEL_ERROR_INVALID_PARAMETER;
    FILE* f = fopen(filepath, "rb");
    if (!f) return SENTINEL_ERROR_IO;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return SENTINEL_ERROR_BUFFER_TOO_SMALL; }
    u8* buf = (u8*)malloc((usize)sz);
    if (!buf) { fclose(f); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    usize rd = fread(buf, 1, (usize)sz, f);
    fclose(f);
    int r = sentinel_pe_parse(buf, rd, info);
    free(buf);
    return r;
}

int sentinel_pe_get_section(const sentinel_pe_info_t* info, const char* name, sentinel_section_t* out) {
    if (!info || !name || !out) return SENTINEL_ERROR_INVALID_PARAMETER;
    for (u32 i = 0; i < info->num_sections && i < 96; i++) {
        if (strncmp(info->sections[i].name, name, 8) == 0) {
            *out = info->sections[i];
            return SENTINEL_OK;
        }
    }
    return SENTINEL_ERROR_NOT_FOUND;
}

u32 sentinel_pe_rva_to_offset(const sentinel_pe_info_t* info, u32 rva) {
    if (!info) return 0;
    for (u32 i = 0; i < info->num_sections && i < 96; i++) {
        if (rva >= info->sections[i].virtual_address &&
            rva < info->sections[i].virtual_address + info->sections[i].virtual_size)
            return info->sections[i].raw_offset + (rva - info->sections[i].virtual_address);
    }
    return 0;
}

int sentinel_pe_enum_imports(const u8* data, usize size, sentinel_enum_callback_t cb, void* ctx) {
    if (!data || !cb) return SENTINEL_ERROR_INVALID_PARAMETER;
    sentinel_pe_info_t pe = {};
    int rc = sentinel_pe_parse(data, size, &pe);
    if (rc != SENTINEL_OK) return rc;
    const sentinel_dos_header_t* dos = (const sentinel_dos_header_t*)data;
    const u8* coff = data + dos->e_lfanew + 4;
    const u8* opt = coff + 20;
    u16 m = *(const u16*)opt;
    u32 irva = (m == PE_OPT64_MAGIC) ? *(const u32*)(opt+120) : *(const u32*)(opt+104);
    if (irva == 0) return SENTINEL_OK;
    u32 ioff = sentinel_pe_rva_to_offset(&pe, irva);
    if (ioff == 0) return SENTINEL_OK;
    const u8* d = data + ioff;
    while (d+20 <= data+size) {
        u32 nrva = *(const u32*)(d+12);
        if (nrva == 0) break;
        u32 no = sentinel_pe_rva_to_offset(&pe, nrva);
        if (no > 0 && no < size) {
            sentinel_import_t imp = {};
            strncpy(imp.dll_name, (const char*)(data+no), SENTINEL_MAX_MODULE_NAME-1);
            imp.original_first_thunk = *(const u32*)d;
            imp.first_thunk = *(const u32*)(d+16);
            if (!cb(&imp, ctx)) break;
        }
        d += 20;
    }
    return SENTINEL_OK;
}

int sentinel_pe_enum_exports(const u8* data, usize size, sentinel_enum_callback_t cb, void* ctx) {
    if (!data || !cb) return SENTINEL_ERROR_INVALID_PARAMETER;
    sentinel_pe_info_t pe = {};
    int rc = sentinel_pe_parse(data, size, &pe);
    if (rc != SENTINEL_OK) return rc;
    const sentinel_dos_header_t* dos = (const sentinel_dos_header_t*)data;
    const u8* coff = data + dos->e_lfanew + 4;
    const u8* opt = coff + 20;
    u16 m = *(const u16*)opt;
    u32 erva = (m == PE_OPT64_MAGIC) ? *(const u32*)(opt+112) : *(const u32*)(opt+96);
    if (erva == 0) return SENTINEL_OK;
    u32 eoff = sentinel_pe_rva_to_offset(&pe, erva);
    if (eoff == 0 || eoff+40 > size) return SENTINEL_OK;
    const u8* ed = data+eoff;
    u32 nn = *(const u32*)(ed+24);
    u32 fo = sentinel_pe_rva_to_offset(&pe, *(const u32*)(ed+28));
    u32 no = sentinel_pe_rva_to_offset(&pe, *(const u32*)(ed+32));
    u32 oo = sentinel_pe_rva_to_offset(&pe, *(const u32*)(ed+36));
    u32 bo = *(const u32*)(ed+16);
    for (u32 i = 0; i < nn; i++) {
        sentinel_export_t ex = {};
        if (no && no+i*4+4 <= size) {
            u32 r = *(const u32*)(data+no+i*4);
            u32 o = sentinel_pe_rva_to_offset(&pe, r);
            if (o > 0 && o < size) strncpy(ex.name, (const char*)(data+o), SENTINEL_MAX_MODULE_NAME-1);
        }
        if (oo && oo+i*2+2 <= size) {
            u16 idx = *(const u16*)(data+oo+i*2);
            ex.ordinal = bo + idx;
            if (fo+idx*4+4 <= size) ex.rva = *(const u32*)(data+fo+idx*4);
        }
        if (!cb(&ex, ctx)) break;
    }
    return SENTINEL_OK;
}

namespace sentinel { namespace pe {
int Parser::parse(const u8* data, usize size) { return sentinel_pe_parse(data, size, &info_); }
int Parser::parse_file(const char* fp) { return sentinel_pe_parse_file(fp, &info_); }
int Parser::find_section(const char* n, sentinel_section_t* o) const { return sentinel_pe_get_section(&info_, n, o); }
u32 Parser::rva_to_offset(u32 rva) const { return sentinel_pe_rva_to_offset(&info_, rva); }
}}

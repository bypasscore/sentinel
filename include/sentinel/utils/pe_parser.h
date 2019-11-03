#ifndef SENTINEL_UTILS_PE_PARSER_H
#define SENTINEL_UTILS_PE_PARSER_H

#include "sentinel/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentinel_dos_header {
    u16 e_magic;
    u16 e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    u16 e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    u16 e_res[4];
    u16 e_oemid, e_oeminfo;
    u16 e_res2[10];
    i32 e_lfanew;
} sentinel_dos_header_t;

typedef struct sentinel_section {
    char    name[8];
    u32     virtual_size;
    u32     virtual_address;
    u32     raw_size;
    u32     raw_offset;
    u32     reloc_offset;
    u32     linenum_offset;
    u16     num_relocs;
    u16     num_linenums;
    u32     characteristics;
} sentinel_section_t;

typedef struct sentinel_import {
    char    dll_name[SENTINEL_MAX_MODULE_NAME];
    u32     original_first_thunk;
    u32     first_thunk;
    u32     timestamp;
} sentinel_import_t;

typedef struct sentinel_export {
    char    name[SENTINEL_MAX_MODULE_NAME];
    u32     ordinal;
    u32     rva;
    bool    is_forwarded;
    char    forward_name[SENTINEL_MAX_MODULE_NAME];
} sentinel_export_t;

typedef struct sentinel_pe_info {
    bool    is_valid;
    bool    is_64bit;
    bool    is_dll;
    bool    is_driver;
    u16     machine;
    u32     num_sections;
    u32     entry_point_rva;
    u64     image_base;
    u32     image_size;
    u32     checksum;
    u32     subsystem;
    u32     dll_characteristics;
    u32     timestamp;
    sentinel_section_t sections[96];
} sentinel_pe_info_t;

int sentinel_pe_parse(const u8* data, usize size, sentinel_pe_info_t* info);
int sentinel_pe_parse_file(const char* filepath, sentinel_pe_info_t* info);
int sentinel_pe_get_section(const sentinel_pe_info_t* info, const char* name, sentinel_section_t* out);
int sentinel_pe_enum_imports(const u8* data, usize size, sentinel_enum_callback_t cb, void* ctx);
int sentinel_pe_enum_exports(const u8* data, usize size, sentinel_enum_callback_t cb, void* ctx);
u32 sentinel_pe_rva_to_offset(const sentinel_pe_info_t* info, u32 rva);
bool sentinel_pe_is_valid(const u8* data, usize size);

#ifdef __cplusplus
}

namespace sentinel { namespace pe {

class Parser {
public:
    Parser() = default;
    int parse(const u8* data, usize size);
    int parse_file(const char* filepath);
    bool is_valid() const { return info_.is_valid; }
    bool is_64bit() const { return info_.is_64bit; }
    bool is_dll() const { return info_.is_dll; }
    bool is_driver() const { return info_.is_driver; }
    u32 entry_point() const { return info_.entry_point_rva; }
    u64 image_base() const { return info_.image_base; }
    u32 image_size() const { return info_.image_size; }
    u32 section_count() const { return info_.num_sections; }
    const sentinel_pe_info_t& info() const { return info_; }
    int find_section(const char* name, sentinel_section_t* out) const;
    u32 rva_to_offset(u32 rva) const;
private:
    sentinel_pe_info_t info_ = {};
};

}}
#endif
#endif

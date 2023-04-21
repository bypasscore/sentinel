#include "sentinel/detection/syscall.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/pe_parser.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

bool sentinel_is_function_hooked(sentinel_addr_t func_addr) {
    if (!func_addr) return false;
    const u8* bytes = (const u8*)func_addr;

    /* Check for common hook patterns */
    /* JMP rel32: E9 xx xx xx xx */
    if (bytes[0] == 0xE9) return true;

    /* MOV RAX, imm64; JMP RAX: 48 B8 xx xx xx xx xx xx xx xx FF E0 */
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true;

    /* JMP [rip+0]: FF 25 00 00 00 00 */
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;

    /* INT 3 breakpoint: CC */
    if (bytes[0] == 0xCC) return true;

    /* Push/ret trampoline: 68 xx xx xx xx C3 */
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) return true;

    return false;
}

int sentinel_check_ntdll_integrity(u32* num_hooks) {
    if (!num_hooks) return SENTINEL_ERROR_INVALID_PARAMETER;
    *num_hooks = 0;

    /* Load a fresh copy of ntdll from disk to compare against */
    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    char ntdll_path[MAX_PATH];
    snprintf(ntdll_path, MAX_PATH, "%s\ntdll.dll", sys_dir);

    /* Read the file */
    FILE* f = fopen(ntdll_path, "rb");
    if (!f) return SENTINEL_ERROR_IO;
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* file_data = (u8*)malloc(file_size);
    if (!file_data) { fclose(f); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    fread(file_data, 1, file_size, f);
    fclose(f);

    sentinel_pe_info_t pe = {};
    int rc = sentinel_pe_parse(file_data, file_size, &pe);
    if (rc != SENTINEL_OK) { free(file_data); return rc; }

    /* Get the .text section from the file */
    sentinel_section_t text_sec = {};
    rc = sentinel_pe_get_section(&pe, ".text", &text_sec);
    if (rc != SENTINEL_OK) { free(file_data); return rc; }

    /* Get the in-memory ntdll */
    HMODULE ntdll_mem = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll_mem) { free(file_data); return SENTINEL_ERROR_MODULE_NOT_FOUND; }

    const u8* mem_text = (const u8*)ntdll_mem + text_sec.virtual_address;
    const u8* file_text = file_data + text_sec.raw_offset;
    usize compare_size = text_sec.raw_size < text_sec.virtual_size
                         ? text_sec.raw_size : text_sec.virtual_size;

    /* Compare byte by byte, looking for modifications */
    u32 hooks = 0;
    for (usize i = 0; i < compare_size; i++) {
        if (mem_text[i] != file_text[i]) {
            /* Found a modification -- count contiguous modified regions as one hook */
            hooks++;
            while (i < compare_size && mem_text[i] != file_text[i]) i++;
        }
    }

    *num_hooks = hooks;
    free(file_data);

    if (hooks > 0)
        SLOG_WARN("ntdll.dll integrity check: %u hooks/patches detected", hooks);
    else
        SLOG_INFO("ntdll.dll integrity check: clean");

    return SENTINEL_OK;
}

int sentinel_detect_syscall_hooks(sentinel_enum_callback_t cb, void* ctx) {
    if (!cb) return SENTINEL_ERROR_INVALID_PARAMETER;

    static const char* critical_functions[] = {
        "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "NtOpenProcess", "NtQuerySystemInformation",
        "NtQueryInformationProcess", "NtCreateThreadEx",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtDeviceIoControlFile", "NtQueryVirtualMemory",
        "NtCreateFile", "NtDuplicateObject",
        "LdrLoadDll", nullptr
    };

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return SENTINEL_ERROR_MODULE_NOT_FOUND;

    for (int i = 0; critical_functions[i]; i++) {
        FARPROC addr = GetProcAddress(ntdll, critical_functions[i]);
        if (!addr) continue;

        sentinel_syscall_info_t info = {};
        strncpy(info.function_name, critical_functions[i], sizeof(info.function_name)-1);
        info.current_address = (sentinel_addr_t)addr;
        memcpy(info.current_bytes, (const u8*)addr, 16);
        info.is_hooked = sentinel_is_function_hooked((sentinel_addr_t)addr);

        if (!cb(&info, ctx)) break;
    }

    return SENTINEL_OK;
}

int sentinel_get_clean_syscall_stub(const char* function_name, u8* stub, usize stub_size) {
    if (!function_name || !stub || stub_size < 32)
        return SENTINEL_ERROR_INVALID_PARAMETER;

    /* Read clean ntdll from disk and extract the syscall stub */
    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\ntdll.dll", sys_dir);

    FILE* f = fopen(path, "rb");
    if (!f) return SENTINEL_ERROR_IO;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8* data = (u8*)malloc(sz);
    if (!data) { fclose(f); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    fread(data, 1, sz, f);
    fclose(f);

    sentinel_pe_info_t pe = {};
    sentinel_pe_parse(data, sz, &pe);

    /* Find the export */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC func = GetProcAddress(ntdll, function_name);
    if (!func) { free(data); return SENTINEL_ERROR_NOT_FOUND; }

    sentinel_addr_t rva = (sentinel_addr_t)func - (sentinel_addr_t)ntdll;
    u32 file_off = sentinel_pe_rva_to_offset(&pe, (u32)rva);
    if (file_off == 0 || file_off + stub_size > (usize)sz) {
        free(data);
        return SENTINEL_ERROR_NOT_FOUND;
    }

    memcpy(stub, data + file_off, stub_size);
    free(data);
    return SENTINEL_OK;
}

#else
bool sentinel_is_function_hooked(sentinel_addr_t a) { (void)a; return false; }
int sentinel_detect_syscall_hooks(sentinel_enum_callback_t c, void* x) { (void)c;(void)x; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_check_ntdll_integrity(u32* n) { (void)n; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_get_clean_syscall_stub(const char* f, u8* s, usize z) { (void)f;(void)s;(void)z; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

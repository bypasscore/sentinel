#include "sentinel/process/hide.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

/* PEB_LDR_DATA and LDR_DATA_TABLE_ENTRY structures */
typedef struct _SENTINEL_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
} SENTINEL_LDR_ENTRY;

static void unlink_list_entry(LIST_ENTRY* entry) {
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;
    entry->Flink = entry;
    entry->Blink = entry;
}

int sentinel_hide_module_from_peb(const char* module_name) {
    if (!module_name) return SENTINEL_ERROR_INVALID_PARAMETER;

    /* Convert module name to wide string for comparison */
    wchar_t wide_name[SENTINEL_MAX_MODULE_NAME];
    MultiByteToWideChar(CP_ACP, 0, module_name, -1, wide_name, SENTINEL_MAX_MODULE_NAME);

    /* Access the PEB through the TEB */
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr) return SENTINEL_ERROR_NOT_FOUND;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        SENTINEL_LDR_ENTRY* entry = CONTAINING_RECORD(curr, SENTINEL_LDR_ENTRY, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer) {
            if (_wcsicmp(entry->BaseDllName.Buffer, wide_name) == 0) {
                /* Unlink from all three PEB lists */
                unlink_list_entry(&entry->InLoadOrderLinks);
                unlink_list_entry(&entry->InMemoryOrderLinks);
                unlink_list_entry(&entry->InInitializationOrderLinks);

                /* Zero out the name to prevent string-based detection */
                memset(entry->BaseDllName.Buffer, 0, entry->BaseDllName.Length);
                memset(entry->FullDllName.Buffer, 0, entry->FullDllName.Length);
                entry->BaseDllName.Length = 0;
                entry->FullDllName.Length = 0;

                SLOG_INFO("Module hidden from PEB: %s", module_name);
                return SENTINEL_OK;
            }
        }
        curr = curr->Flink;
    }
    return SENTINEL_ERROR_MODULE_NOT_FOUND;
}

int sentinel_erase_pe_headers(sentinel_handle_t process, sentinel_addr_t module_base) {
    if (!module_base) return SENTINEL_ERROR_INVALID_PARAMETER;

    DWORD old_prot;
    if (!VirtualProtectEx((HANDLE)process, (LPVOID)module_base, 0x1000,
                          PAGE_READWRITE, &old_prot))
        return SENTINEL_ERROR_ACCESS_DENIED;

    u8 zeros[0x1000] = {};
    SIZE_T written;
    WriteProcessMemory((HANDLE)process, (LPVOID)module_base, zeros, sizeof(zeros), &written);
    VirtualProtectEx((HANDLE)process, (LPVOID)module_base, 0x1000, old_prot, &old_prot);

    return SENTINEL_OK;
}

int sentinel_hide_module(sentinel_handle_t process, const char* module_name) {
    int rc = sentinel_hide_module_from_peb(module_name);
    if (rc != SENTINEL_OK) return rc;

    HMODULE hmod = GetModuleHandleA(module_name);
    if (hmod) sentinel_erase_pe_headers(process, (sentinel_addr_t)hmod);
    return SENTINEL_OK;
}

int sentinel_unlink_module_from_ldr(sentinel_addr_t ldr_entry) {
    if (!ldr_entry) return SENTINEL_ERROR_INVALID_PARAMETER;
    SENTINEL_LDR_ENTRY* entry = (SENTINEL_LDR_ENTRY*)ldr_entry;
    unlink_list_entry(&entry->InLoadOrderLinks);
    unlink_list_entry(&entry->InMemoryOrderLinks);
    unlink_list_entry(&entry->InInitializationOrderLinks);
    return SENTINEL_OK;
}

int sentinel_spoof_module_name(const char* real_name, const char* fake_name) {
    if (!real_name || !fake_name) return SENTINEL_ERROR_INVALID_PARAMETER;
    wchar_t wide_real[SENTINEL_MAX_MODULE_NAME], wide_fake[SENTINEL_MAX_MODULE_NAME];
    MultiByteToWideChar(CP_ACP, 0, real_name, -1, wide_real, SENTINEL_MAX_MODULE_NAME);
    MultiByteToWideChar(CP_ACP, 0, fake_name, -1, wide_fake, SENTINEL_MAX_MODULE_NAME);

#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return SENTINEL_ERROR_NOT_FOUND;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        SENTINEL_LDR_ENTRY* e = CONTAINING_RECORD(curr, SENTINEL_LDR_ENTRY, InMemoryOrderLinks);
        if (e->BaseDllName.Buffer && _wcsicmp(e->BaseDllName.Buffer, wide_real) == 0) {
            usize fake_len = wcslen(wide_fake) * sizeof(wchar_t);
            if (fake_len <= e->BaseDllName.MaximumLength) {
                memcpy(e->BaseDllName.Buffer, wide_fake, fake_len + sizeof(wchar_t));
                e->BaseDllName.Length = (USHORT)fake_len;
                return SENTINEL_OK;
            }
        }
        curr = curr->Flink;
    }
    return SENTINEL_ERROR_MODULE_NOT_FOUND;
}

#else
int sentinel_hide_module(sentinel_handle_t p, const char* n) { (void)p;(void)n; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_hide_module_from_peb(const char* n) { (void)n; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_unlink_module_from_ldr(sentinel_addr_t e) { (void)e; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_spoof_module_name(const char* r, const char* f) { (void)r;(void)f; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_erase_pe_headers(sentinel_handle_t p, sentinel_addr_t b) { (void)p;(void)b; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

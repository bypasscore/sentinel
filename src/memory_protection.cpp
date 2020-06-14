#include "sentinel/memory/protection.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static DWORD to_win32_prot(sentinel_protection_t p) {
    switch (p) {
        case SENTINEL_PROT_NOACCESS:          return PAGE_NOACCESS;
        case SENTINEL_PROT_READONLY:          return PAGE_READONLY;
        case SENTINEL_PROT_READWRITE:         return PAGE_READWRITE;
        case SENTINEL_PROT_EXECUTE:           return PAGE_EXECUTE;
        case SENTINEL_PROT_EXECUTE_READ:      return PAGE_EXECUTE_READ;
        case SENTINEL_PROT_EXECUTE_READWRITE: return PAGE_EXECUTE_READWRITE;
        default: return PAGE_READWRITE;
    }
}

static sentinel_protection_t from_win32_prot(DWORD p) {
    if (p & PAGE_EXECUTE_READWRITE)  return SENTINEL_PROT_EXECUTE_READWRITE;
    if (p & PAGE_EXECUTE_READ)       return SENTINEL_PROT_EXECUTE_READ;
    if (p & PAGE_EXECUTE_WRITECOPY)  return SENTINEL_PROT_EXECUTE_WRITECOPY;
    if (p & PAGE_EXECUTE)            return SENTINEL_PROT_EXECUTE;
    if (p & PAGE_READWRITE)          return SENTINEL_PROT_READWRITE;
    if (p & PAGE_WRITECOPY)          return SENTINEL_PROT_WRITECOPY;
    if (p & PAGE_READONLY)           return SENTINEL_PROT_READONLY;
    return SENTINEL_PROT_NOACCESS;
}

int sentinel_mem_protect(sentinel_handle_t process, sentinel_addr_t address,
                         usize size, sentinel_protection_t new_prot,
                         sentinel_protection_t* old_prot) {
    DWORD old_win = 0;
    if (!VirtualProtectEx((HANDLE)process, (LPVOID)address, size,
                          to_win32_prot(new_prot), &old_win))
        return SENTINEL_ERROR_ACCESS_DENIED;
    if (old_prot) *old_prot = from_win32_prot(old_win);
    return SENTINEL_OK;
}

int sentinel_mem_query(sentinel_handle_t process, sentinel_addr_t address,
                       sentinel_region_t* region) {
    if (!region) return SENTINEL_ERROR_INVALID_PARAMETER;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx((HANDLE)process, (LPCVOID)address, &mbi, sizeof(mbi)))
        return SENTINEL_ERROR_NOT_FOUND;
    region->base = (sentinel_addr_t)mbi.BaseAddress;
    region->size = mbi.RegionSize;
    region->protection = from_win32_prot(mbi.Protect);
    region->state = mbi.State;
    region->type = mbi.Type;
    return SENTINEL_OK;
}

int sentinel_mem_enum_regions(sentinel_handle_t process,
                              sentinel_enum_callback_t callback, void* ctx) {
    if (!callback) return SENTINEL_ERROR_INVALID_PARAMETER;
    sentinel_addr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx((HANDLE)process, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        sentinel_region_t reg = {};
        reg.base = (sentinel_addr_t)mbi.BaseAddress;
        reg.size = mbi.RegionSize;
        reg.protection = from_win32_prot(mbi.Protect);
        reg.state = mbi.State;
        reg.type = mbi.Type;
        if (!callback(&reg, ctx)) break;
        addr = reg.base + reg.size;
    }
    return SENTINEL_OK;
}

int sentinel_mem_read(sentinel_handle_t process, sentinel_addr_t address,
                      void* buffer, usize size, usize* bytes_read) {
    SIZE_T read = 0;
    if (!ReadProcessMemory((HANDLE)process, (LPCVOID)address, buffer, size, &read))
        return SENTINEL_ERROR_ACCESS_DENIED;
    if (bytes_read) *bytes_read = (usize)read;
    return SENTINEL_OK;
}

int sentinel_mem_write(sentinel_handle_t process, sentinel_addr_t address,
                       const void* buffer, usize size, usize* bytes_written) {
    SIZE_T written = 0;
    if (!WriteProcessMemory((HANDLE)process, (LPVOID)address, buffer, size, &written))
        return SENTINEL_ERROR_ACCESS_DENIED;
    if (bytes_written) *bytes_written = (usize)written;
    return SENTINEL_OK;
}

int sentinel_mem_write_protected(sentinel_handle_t process,
                                  sentinel_addr_t address,
                                  const void* buffer, usize size) {
    sentinel_protection_t old_prot;
    int rc = sentinel_mem_protect(process, address, size,
                                   SENTINEL_PROT_EXECUTE_READWRITE, &old_prot);
    if (rc != SENTINEL_OK) return rc;
    usize written = 0;
    rc = sentinel_mem_write(process, address, buffer, size, &written);
    sentinel_mem_protect(process, address, size, old_prot, nullptr);
    return rc;
}

#else
int sentinel_mem_protect(sentinel_handle_t p, sentinel_addr_t a, usize s,
    sentinel_protection_t n, sentinel_protection_t* o) { (void)p;(void)a;(void)s;(void)n;(void)o; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_mem_query(sentinel_handle_t p, sentinel_addr_t a, sentinel_region_t* r) { (void)p;(void)a;(void)r; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_mem_enum_regions(sentinel_handle_t p, sentinel_enum_callback_t c, void* x) { (void)p;(void)c;(void)x; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_mem_read(sentinel_handle_t p, sentinel_addr_t a, void* b, usize s, usize* r) { (void)p;(void)a;(void)b;(void)s;(void)r; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_mem_write(sentinel_handle_t p, sentinel_addr_t a, const void* b, usize s, usize* w) { (void)p;(void)a;(void)b;(void)s;(void)w; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_mem_write_protected(sentinel_handle_t p, sentinel_addr_t a, const void* b, usize s) { (void)p;(void)a;(void)b;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

#include "sentinel/memory/allocator.h"
#include "sentinel/memory/protection.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static DWORD prot_to_win32(sentinel_protection_t p) {
    switch (p) {
        case SENTINEL_PROT_EXECUTE_READWRITE: return PAGE_EXECUTE_READWRITE;
        case SENTINEL_PROT_EXECUTE_READ: return PAGE_EXECUTE_READ;
        case SENTINEL_PROT_READWRITE: return PAGE_READWRITE;
        default: return PAGE_READWRITE;
    }
}

sentinel_addr_t sentinel_alloc(sentinel_handle_t process, usize size,
                                const sentinel_alloc_config_t* config) {
    if (!process || size == 0) return 0;
    DWORD prot = config ? prot_to_win32(config->protection) : PAGE_READWRITE;
    LPVOID preferred = config ? (LPVOID)config->preferred_address : nullptr;

    if (config && config->strategy == SENTINEL_ALLOC_NEAR_ADDRESS) {
        return sentinel_alloc_near(process, config->preferred_address, size, config->protection);
    }

    LPVOID addr = VirtualAllocEx((HANDLE)process, preferred, size,
                                  MEM_COMMIT | MEM_RESERVE, prot);
    if (!addr && preferred) {
        addr = VirtualAllocEx((HANDLE)process, nullptr, size,
                              MEM_COMMIT | MEM_RESERVE, prot);
    }
    if (addr && config && config->zero_memory) {
        /* Memory from VirtualAlloc is already zeroed, but be safe for remote */
        u8* zeros = (u8*)calloc(1, size);
        if (zeros) {
            SIZE_T written;
            WriteProcessMemory((HANDLE)process, addr, zeros, size, &written);
            free(zeros);
        }
    }
    return (sentinel_addr_t)addr;
}

int sentinel_free(sentinel_handle_t process, sentinel_addr_t address, usize size) {
    (void)size;
    if (!VirtualFreeEx((HANDLE)process, (LPVOID)address, 0, MEM_RELEASE))
        return SENTINEL_ERROR_ACCESS_DENIED;
    return SENTINEL_OK;
}

sentinel_addr_t sentinel_alloc_near(sentinel_handle_t process,
                                     sentinel_addr_t target, usize size,
                                     sentinel_protection_t prot) {
    /* Try to allocate within +/- 2GB of target for relative jumps */
    const sentinel_addr_t range = 0x7FFF0000ULL;
    sentinel_addr_t low = (target > range) ? target - range : 0x10000;
    sentinel_addr_t high = target + range;

    MEMORY_BASIC_INFORMATION mbi;
    sentinel_addr_t addr = low;
    while (addr < high) {
        if (!VirtualQueryEx((HANDLE)process, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            LPVOID alloc = VirtualAllocEx((HANDLE)process, (LPVOID)addr,
                                          size, MEM_COMMIT | MEM_RESERVE,
                                          prot_to_win32(prot));
            if (alloc) return (sentinel_addr_t)alloc;
        }
        addr = (sentinel_addr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;
}

sentinel_addr_t sentinel_find_code_cave(sentinel_handle_t process,
                                         const char* module_name,
                                         usize min_size) {
    /* Find a sequence of null bytes in a module section padding */
    (void)process; (void)module_name; (void)min_size;
    SLOG_WARN("find_code_cave: not yet fully implemented");
    return 0;
}

#else
sentinel_addr_t sentinel_alloc(sentinel_handle_t p, usize s, const sentinel_alloc_config_t* c) { (void)p;(void)s;(void)c; return 0; }
int sentinel_free(sentinel_handle_t p, sentinel_addr_t a, usize s) { (void)p;(void)a;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
sentinel_addr_t sentinel_find_code_cave(sentinel_handle_t p, const char* m, usize s) { (void)p;(void)m;(void)s; return 0; }
sentinel_addr_t sentinel_alloc_near(sentinel_handle_t p, sentinel_addr_t t, usize s, sentinel_protection_t pr) { (void)p;(void)t;(void)s;(void)pr; return 0; }
#endif

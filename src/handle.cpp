#include "sentinel/process/handle.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

/* SystemHandleInformation structures */
#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION_T;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

int sentinel_enum_handles(sentinel_pid_t pid, sentinel_enum_callback_t cb, void* ctx) {
    if (!cb) return SENTINEL_ERROR_INVALID_PARAMETER;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySysInfo = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySysInfo) return SENTINEL_ERROR_NOT_FOUND;

    ULONG buf_size = 1024 * 1024;
    void* buf = malloc(buf_size);
    if (!buf) return SENTINEL_ERROR_OUT_OF_MEMORY;

    NTSTATUS status;
    while ((status = NtQuerySysInfo(SystemHandleInformation, buf, buf_size, nullptr)) == 0xC0000004L) {
        buf_size *= 2;
        void* nb = realloc(buf, buf_size);
        if (!nb) { free(buf); return SENTINEL_ERROR_OUT_OF_MEMORY; }
        buf = nb;
    }

    if (status != 0) { free(buf); return SENTINEL_ERROR_GENERIC; }

    SYSTEM_HANDLE_INFORMATION_T* info = (SYSTEM_HANDLE_INFORMATION_T*)buf;
    for (ULONG i = 0; i < info->HandleCount; i++) {
        SYSTEM_HANDLE_ENTRY* h = &info->Handles[i];
        if (pid != 0 && h->ProcessId != pid) continue;

        sentinel_handle_info_t hi = {};
        hi.handle_value = h->Handle;
        hi.pid = h->ProcessId;
        hi.object_type = h->ObjectTypeNumber;
        hi.granted_access = h->Flags;

        if (!cb(&hi, ctx)) break;
    }

    free(buf);
    return SENTINEL_OK;
}

int sentinel_close_remote_handle(sentinel_pid_t pid, u32 handle_value) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtDupObj = (NtDuplicateObject_t)GetProcAddress(ntdll, "NtDuplicateObject");
    if (!NtDupObj) return SENTINEL_ERROR_NOT_FOUND;

    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;

    HANDLE dup = nullptr;
    NTSTATUS st = NtDupObj(proc, (HANDLE)(uintptr_t)handle_value,
                           GetCurrentProcess(), &dup, 0, 0,
                           0x00000001 /* DUPLICATE_CLOSE_SOURCE */);
    if (dup) CloseHandle(dup);
    CloseHandle(proc);
    return (st == 0) ? SENTINEL_OK : SENTINEL_ERROR_GENERIC;
}

int sentinel_duplicate_handle(sentinel_pid_t source_pid, u32 source_handle,
                               sentinel_handle_t* out_handle) {
    if (!out_handle) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, source_pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    HANDLE dup = nullptr;
    BOOL ok = DuplicateHandle(proc, (HANDLE)(uintptr_t)source_handle,
                              GetCurrentProcess(), &dup, 0, FALSE,
                              DUPLICATE_SAME_ACCESS);
    CloseHandle(proc);
    if (!ok) return SENTINEL_ERROR_ACCESS_DENIED;
    *out_handle = dup;
    return SENTINEL_OK;
}

int sentinel_strip_handle_access(sentinel_pid_t pid, u32 handle_value, u32 access_mask) {
    (void)pid; (void)handle_value; (void)access_mask;
    SLOG_WARN("strip_handle_access: requires kernel-mode support");
    return SENTINEL_ERROR_UNSUPPORTED;
}

#else
int sentinel_enum_handles(sentinel_pid_t p, sentinel_enum_callback_t c, void* x) { (void)p;(void)c;(void)x; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_close_remote_handle(sentinel_pid_t p, u32 h) { (void)p;(void)h; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_duplicate_handle(sentinel_pid_t p, u32 h, sentinel_handle_t* o) { (void)p;(void)h;(void)o; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_strip_handle_access(sentinel_pid_t p, u32 h, u32 m) { (void)p;(void)h;(void)m; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

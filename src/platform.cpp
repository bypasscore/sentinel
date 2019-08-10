#include "sentinel/core/platform.h"
#include "sentinel/core/error.h"

#ifdef SENTINEL_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

typedef NTSTATUS(NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);

int sentinel_get_os_version(sentinel_os_version_t* version) {
    if (!version) return SENTINEL_ERROR_INVALID_PARAMETER;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return SENTINEL_ERROR_MODULE_NOT_FOUND;

    auto fn = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return SENTINEL_ERROR_NOT_FOUND;

    RTL_OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0) return SENTINEL_ERROR_GENERIC;

    version->major = vi.dwMajorVersion;
    version->minor = vi.dwMinorVersion;
    version->build = vi.dwBuildNumber;
    version->is_server = false;
    return SENTINEL_OK;
}

bool sentinel_is_elevated(void) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elev = {};
    DWORD size = 0;
    bool result = false;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
        result = (elev.TokenIsElevated != 0);
    CloseHandle(token);
    return result;
}

bool sentinel_is_secure_boot(void) {
    DWORD val = 0, size = sizeof(val);
    DWORD ret = GetFirmwareEnvironmentVariableW(
        L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &val, size);
    return (ret != 0 && val == 1);
}

bool sentinel_is_vbs_enabled(void) {
    HKEY hkey = nullptr;
    LONG st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        0, KEY_READ, &hkey);
    if (st != ERROR_SUCCESS) return false;

    DWORD val = 0, size = sizeof(val), type = 0;
    st = RegQueryValueExW(hkey, L"EnableVirtualizationBasedSecurity",
                          nullptr, &type, (LPBYTE)&val, &size);
    RegCloseKey(hkey);
    return (st == ERROR_SUCCESS && val == 1);
}

bool sentinel_is_hypervisor_present(void) {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

int sentinel_enable_debug_privilege(void) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return SENTINEL_ERROR_ACCESS_DENIED;

    LUID luid = {};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return SENTINEL_ERROR_NOT_FOUND;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);

    if (!ok || err == ERROR_NOT_ALL_ASSIGNED)
        return SENTINEL_ERROR_ACCESS_DENIED;
    return SENTINEL_OK;
}

#else
int sentinel_get_os_version(sentinel_os_version_t* v) { (void)v; return SENTINEL_ERROR_UNSUPPORTED; }
bool sentinel_is_elevated(void) { return false; }
bool sentinel_is_secure_boot(void) { return false; }
bool sentinel_is_vbs_enabled(void) { return false; }
bool sentinel_is_hypervisor_present(void) { return false; }
int sentinel_enable_debug_privilege(void) { return SENTINEL_ERROR_UNSUPPORTED; }
#endif

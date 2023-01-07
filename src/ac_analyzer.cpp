#include "sentinel/detection/analyzer.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

/* Known anti-cheat process names */
static const struct { const char* proc_name; sentinel_ac_type_t type; const char* display; } ac_processes[] = {
    { "EasyAntiCheat.exe", SENTINEL_AC_EAC, "Easy Anti-Cheat" },
    { "EasyAntiCheat_EOS.exe", SENTINEL_AC_EAC, "Easy Anti-Cheat (EOS)" },
    { "BEService.exe", SENTINEL_AC_BATTLEYE, "BattlEye" },
    { "BEClient_x64.dll", SENTINEL_AC_BATTLEYE, "BattlEye" },
    { "vgc.exe", SENTINEL_AC_VANGUARD, "Riot Vanguard" },
    { "vgtray.exe", SENTINEL_AC_VANGUARD, "Riot Vanguard" },
    { "xhunter1.sys", SENTINEL_AC_XIGNCODE, "XIGNCODE3" },
    { "GameMon.des", SENTINEL_AC_GAMEGUARD, "nProtect GameGuard" },
};

/* Known anti-cheat driver names */
static const struct { const char* drv_name; sentinel_ac_type_t type; } ac_drivers[] = {
    { "EasyAntiCheat", SENTINEL_AC_EAC },
    { "EasyAntiCheatSys", SENTINEL_AC_EAC },
    { "BEDaisy", SENTINEL_AC_BATTLEYE },
    { "vgk", SENTINEL_AC_VANGUARD },
    { "xhunter1", SENTINEL_AC_XIGNCODE },
    { "npggsvc", SENTINEL_AC_GAMEGUARD },
};

static bool find_process(const char* name, DWORD* out_pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = {}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                if (out_pid) *out_pid = pe.th32ProcessID;
                CloseHandle(snap);
                return true;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

static bool check_driver(const char* service_name) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return false; }
    SERVICE_STATUS status;
    QueryServiceStatus(svc, &status);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return (status.dwCurrentState == SERVICE_RUNNING);
}

int sentinel_ac_detect(sentinel_ac_info_t* info) {
    if (!info) return SENTINEL_ERROR_INVALID_PARAMETER;
    memset(info, 0, sizeof(*info));

    for (size_t i = 0; i < sizeof(ac_processes)/sizeof(ac_processes[0]); i++) {
        DWORD pid = 0;
        if (find_process(ac_processes[i].proc_name, &pid)) {
            info->type = ac_processes[i].type;
            strncpy(info->name, ac_processes[i].display, sizeof(info->name)-1);
            info->pid = pid;
            info->user_module_loaded = true;
            SLOG_INFO("Detected anti-cheat: %s (PID %u)", info->name, pid);
            break;
        }
    }

    for (size_t i = 0; i < sizeof(ac_drivers)/sizeof(ac_drivers[0]); i++) {
        if (check_driver(ac_drivers[i].drv_name)) {
            if (info->type == SENTINEL_AC_UNKNOWN)
                info->type = ac_drivers[i].type;
            strncpy(info->driver_name, ac_drivers[i].drv_name, sizeof(info->driver_name)-1);
            info->kernel_module_loaded = true;
            info->is_ring0 = true;
            break;
        }
    }

    if (info->type == SENTINEL_AC_UNKNOWN) return SENTINEL_ERROR_NOT_FOUND;
    return SENTINEL_OK;
}

int sentinel_ac_identify(sentinel_pid_t pid, sentinel_ac_info_t* info) {
    (void)pid; (void)info;
    return SENTINEL_ERROR_UNSUPPORTED;
}

int sentinel_ac_enum_modules(sentinel_pid_t pid, sentinel_enum_callback_t cb, void* ctx) {
    if (!cb) return SENTINEL_ERROR_INVALID_PARAMETER;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return SENTINEL_ERROR_PROCESS_NOT_FOUND;
    MODULEENTRY32 me = {}; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (!cb(me.szModule, ctx)) break;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return SENTINEL_OK;
}

int sentinel_ac_check_detection_vectors(const sentinel_ac_info_t* ac, u32* active_vectors) {
    if (!ac || !active_vectors) return SENTINEL_ERROR_INVALID_PARAMETER;
    *active_vectors = 0;
    switch (ac->type) {
        case SENTINEL_AC_EAC:
            *active_vectors = SENTINEL_DETECT_MEMORY_SCAN | SENTINEL_DETECT_MODULE_ENUM |
                              SENTINEL_DETECT_HANDLE_CHECK | SENTINEL_DETECT_DRIVER_CHECK |
                              SENTINEL_DETECT_SYSCALL_HOOK | SENTINEL_DETECT_DEBUG_CHECK;
            break;
        case SENTINEL_AC_BATTLEYE:
            *active_vectors = SENTINEL_DETECT_MEMORY_SCAN | SENTINEL_DETECT_MODULE_ENUM |
                              SENTINEL_DETECT_HANDLE_CHECK | SENTINEL_DETECT_THREAD_CHECK |
                              SENTINEL_DETECT_TIMING_CHECK;
            break;
        case SENTINEL_AC_VANGUARD:
            *active_vectors = SENTINEL_DETECT_MEMORY_SCAN | SENTINEL_DETECT_DRIVER_CHECK |
                              SENTINEL_DETECT_HYPERVISOR | SENTINEL_DETECT_SYSCALL_HOOK |
                              SENTINEL_DETECT_DEBUG_CHECK | SENTINEL_DETECT_HANDLE_CHECK;
            break;
        default:
            *active_vectors = SENTINEL_DETECT_MEMORY_SCAN;
            break;
    }
    return SENTINEL_OK;
}

#else
int sentinel_ac_detect(sentinel_ac_info_t* i) { (void)i; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_ac_identify(sentinel_pid_t p, sentinel_ac_info_t* i) { (void)p;(void)i; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_ac_enum_modules(sentinel_pid_t p, sentinel_enum_callback_t c, void* x) { (void)p;(void)c;(void)x; return SENTINEL_ERROR_UNSUPPORTED; }
int sentinel_ac_check_detection_vectors(const sentinel_ac_info_t* a, u32* v) { (void)a;(void)v; return SENTINEL_ERROR_UNSUPPORTED; }
#endif

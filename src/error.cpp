#include "sentinel/core/error.h"
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

static const struct { int code; const char* msg; } error_table[] = {
    { SENTINEL_OK,                         "Success" },
    { SENTINEL_ERROR_GENERIC,              "Generic error" },
    { SENTINEL_ERROR_INVALID_PARAMETER,    "Invalid parameter" },
    { SENTINEL_ERROR_OUT_OF_MEMORY,        "Out of memory" },
    { SENTINEL_ERROR_ACCESS_DENIED,        "Access denied" },
    { SENTINEL_ERROR_NOT_FOUND,            "Not found" },
    { SENTINEL_ERROR_ALREADY_EXISTS,       "Already exists" },
    { SENTINEL_ERROR_ALREADY_INITIALIZED,  "Already initialized" },
    { SENTINEL_ERROR_NOT_INITIALIZED,      "Not initialized" },
    { SENTINEL_ERROR_TIMEOUT,              "Operation timed out" },
    { SENTINEL_ERROR_BUFFER_TOO_SMALL,     "Buffer too small" },
    { SENTINEL_ERROR_UNSUPPORTED,          "Unsupported" },
    { SENTINEL_ERROR_IO,                   "I/O error" },
    { SENTINEL_ERROR_DRIVER_LOAD_FAILED,   "Driver load failed" },
    { SENTINEL_ERROR_DRIVER_COMM_FAILED,   "Driver comm failed" },
    { SENTINEL_ERROR_PROCESS_NOT_FOUND,    "Process not found" },
    { SENTINEL_ERROR_MODULE_NOT_FOUND,     "Module not found" },
    { SENTINEL_ERROR_PATTERN_INVALID,      "Invalid pattern" },
    { SENTINEL_ERROR_SIGNATURE_MISMATCH,   "Signature mismatch" },
    { SENTINEL_ERROR_INTEGRITY_VIOLATION,  "Integrity violation" },
    { SENTINEL_ERROR_HOOK_DETECTED,        "Hook detected" },
    { SENTINEL_ERROR_VBS_ENABLED,          "VBS enabled" },
};

const char* sentinel_error_string(int error_code) {
    for (size_t i = 0; i < sizeof(error_table) / sizeof(error_table[0]); i++) {
        if (error_table[i].code == error_code) return error_table[i].msg;
    }
    return "Unknown error";
}

u32 sentinel_last_os_error(void) {
#ifdef _WIN32
    return (u32)GetLastError();
#else
    return 0;
#endif
}

namespace sentinel {

Error Error::from_win32(unsigned long win32_error) {
    char buf[256];
#ifdef _WIN32
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, win32_error, 0, buf, sizeof(buf), nullptr);
#else
    snprintf(buf, sizeof(buf), "Win32 error %lu", win32_error);
#endif
    return Error(SENTINEL_ERROR_GENERIC, buf);
}

Error Error::from_ntstatus(long ntstatus) {
    char buf[64];
    snprintf(buf, sizeof(buf), "NTSTATUS 0x%08lX", (unsigned long)ntstatus);
    return Error(SENTINEL_ERROR_GENERIC, buf);
}

const char* Error::to_string() const {
    if (!message_.empty()) return message_.c_str();
    return sentinel_error_string(code_);
}

} // namespace sentinel

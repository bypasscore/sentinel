#ifndef SENTINEL_CORE_PLATFORM_H
#define SENTINEL_CORE_PLATFORM_H

#include "types.h"

#if defined(_WIN32) || defined(_WIN64)
    #define SENTINEL_PLATFORM_WINDOWS 1
    #ifdef _WIN64
        #define SENTINEL_ARCH_X64 1
    #else
        #define SENTINEL_ARCH_X86 1
    #endif
#elif defined(__linux__)
    #define SENTINEL_PLATFORM_LINUX 1
#else
    #error "Unsupported platform"
#endif

#if defined(_MSC_VER)
    #define SENTINEL_COMPILER_MSVC 1
    #define SENTINEL_FORCEINLINE __forceinline
    #define SENTINEL_NOINLINE __declspec(noinline)
    #define SENTINEL_ALIGN(n) __declspec(align(n))
#elif defined(__GNUC__) || defined(__clang__)
    #define SENTINEL_COMPILER_GCC 1
    #define SENTINEL_FORCEINLINE __attribute__((always_inline)) inline
    #define SENTINEL_NOINLINE __attribute__((noinline))
    #define SENTINEL_ALIGN(n) __attribute__((aligned(n)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentinel_os_version {
    u32 major;
    u32 minor;
    u32 build;
    bool is_server;
} sentinel_os_version_t;

int sentinel_get_os_version(sentinel_os_version_t* version);
bool sentinel_is_elevated(void);
bool sentinel_is_secure_boot(void);
bool sentinel_is_vbs_enabled(void);
bool sentinel_is_hypervisor_present(void);
int sentinel_enable_debug_privilege(void);

#ifdef __cplusplus
}
#endif

#endif

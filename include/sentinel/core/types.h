#ifndef SENTINEL_CORE_TYPES_H
#define SENTINEL_CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef int8_t    i8;
typedef int16_t   i16;
typedef int32_t   i32;
typedef int64_t   i64;
typedef size_t    usize;

typedef uintptr_t sentinel_addr_t;
typedef uint64_t  sentinel_offset_t;
typedef u32 sentinel_pid_t;
typedef u32 sentinel_tid_t;
typedef void* sentinel_handle_t;

typedef enum sentinel_protection {
    SENTINEL_PROT_NOACCESS          = 0x01,
    SENTINEL_PROT_READONLY          = 0x02,
    SENTINEL_PROT_READWRITE         = 0x04,
    SENTINEL_PROT_WRITECOPY         = 0x08,
    SENTINEL_PROT_EXECUTE           = 0x10,
    SENTINEL_PROT_EXECUTE_READ      = 0x20,
    SENTINEL_PROT_EXECUTE_READWRITE = 0x40,
    SENTINEL_PROT_EXECUTE_WRITECOPY = 0x80,
    SENTINEL_PROT_GUARD             = 0x100,
    SENTINEL_PROT_NOCACHE           = 0x200,
    SENTINEL_PROT_WRITECOMBINE      = 0x400
} sentinel_protection_t;

typedef struct sentinel_region {
    sentinel_addr_t       base;
    usize                 size;
    sentinel_protection_t protection;
    u32                   state;
    u32                   type;
    char                  module_name[260];
} sentinel_region_t;

typedef struct sentinel_match {
    sentinel_addr_t address;
    usize           offset;
    float           confidence;
} sentinel_match_t;

typedef bool (*sentinel_enum_callback_t)(const void* data, void* context);

#define SENTINEL_MAX_PATH        260
#define SENTINEL_MAX_MODULE_NAME 256
#define SENTINEL_MAX_PATTERN_LEN 512
#define SENTINEL_MAX_SIGNATURE   4096
#define SENTINEL_INVALID_HANDLE ((sentinel_handle_t)(intptr_t)-1)

#ifdef __cplusplus
}
#endif

#endif

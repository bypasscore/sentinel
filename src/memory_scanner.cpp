#include "sentinel/memory/scanner.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdlib>
#include <cctype>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#endif

int sentinel_scan_init_result(sentinel_scan_result_t* result, usize cap) {
    if (!result) return SENTINEL_ERROR_INVALID_PARAMETER;
    result->matches = (sentinel_match_t*)calloc(cap, sizeof(sentinel_match_t));
    if (!result->matches) return SENTINEL_ERROR_OUT_OF_MEMORY;
    result->count = 0;
    result->capacity = cap;
    return SENTINEL_OK;
}

void sentinel_scan_free_result(sentinel_scan_result_t* result) {
    if (result && result->matches) {
        free(result->matches);
        result->matches = nullptr;
        result->count = 0;
        result->capacity = 0;
    }
}

static int add_match(sentinel_scan_result_t* r, sentinel_addr_t addr, usize off) {
    if (r->count >= r->capacity) {
        usize nc = r->capacity * 2;
        sentinel_match_t* nm = (sentinel_match_t*)realloc(r->matches, nc * sizeof(sentinel_match_t));
        if (!nm) return SENTINEL_ERROR_OUT_OF_MEMORY;
        r->matches = nm;
        r->capacity = nc;
    }
    r->matches[r->count].address = addr;
    r->matches[r->count].offset = off;
    r->matches[r->count].confidence = 1.0f;
    r->count++;
    return SENTINEL_OK;
}

int sentinel_parse_ida_pattern(const char* pattern, u8* bytes, u8* mask, usize* out_len) {
    if (!pattern || !bytes || !mask || !out_len) return SENTINEL_ERROR_INVALID_PARAMETER;
    usize len = 0;
    const char* p = pattern;
    while (*p && len < SENTINEL_MAX_PATTERN_LEN) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            bytes[len] = 0; mask[len] = 0; len++;
            p++; if (*p == '?') p++;
        } else {
            char hex[3] = {0};
            hex[0] = *p++;
            if (*p && *p != ' ') hex[1] = *p++;
            bytes[len] = (u8)strtoul(hex, nullptr, 16);
            mask[len] = 0xFF; len++;
        }
    }
    *out_len = len;
    return SENTINEL_OK;
}

int sentinel_scan_bytes(const u8* haystack, usize haystack_size,
                        const u8* needle, usize needle_size,
                        const u8* mask, sentinel_scan_result_t* result) {
    if (!haystack || !needle || !result) return SENTINEL_ERROR_INVALID_PARAMETER;
    if (needle_size == 0 || needle_size > haystack_size) return SENTINEL_OK;
    for (usize i = 0; i <= haystack_size - needle_size; i++) {
        /* Skip if alignment requirement not met */
        bool found = true;
        for (usize j = 0; j < needle_size; j++) {
            u8 m = mask ? mask[j] : 0xFF;
            if ((haystack[i+j] & m) != (needle[j] & m)) { found = false; break; }
        }
        if (found) {
            int rc = add_match(result, (sentinel_addr_t)(haystack + i), i);
            if (rc != SENTINEL_OK) return rc;
        }
    }
    return SENTINEL_OK;
}

#ifdef _WIN32
int sentinel_scan_pattern(sentinel_pid_t pid, const char* pattern,
                          const sentinel_scan_config_t* config,
                          sentinel_scan_result_t* result) {
    if (!pattern || !result) return SENTINEL_ERROR_INVALID_PARAMETER;
    u8 bytes[SENTINEL_MAX_PATTERN_LEN], mask[SENTINEL_MAX_PATTERN_LEN];
    usize pat_len = 0;
    int rc = sentinel_parse_ida_pattern(pattern, bytes, mask, &pat_len);
    if (rc != SENTINEL_OK) return rc;

    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return SENTINEL_ERROR_PROCESS_NOT_FOUND;

    sentinel_addr_t addr = config ? config->start_address : 0;
    sentinel_addr_t end_addr = config ? config->end_address : 0x7FFFFFFFFFFF;

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < end_addr && VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD)) {
            u8* buf = (u8*)malloc(mbi.RegionSize);
            if (buf) {
                SIZE_T bytesread = 0;
                if (ReadProcessMemory(proc, mbi.BaseAddress, buf, mbi.RegionSize, &bytesread)) {
                    for (usize i = 0; i + pat_len <= bytesread; i++) {
                        bool match = true;
                        for (usize j = 0; j < pat_len; j++) {
                            if ((buf[i+j] & mask[j]) != (bytes[j] & mask[j])) {
                                match = false; break;
                            }
                        }
                        if (match)
                            add_match(result, (sentinel_addr_t)mbi.BaseAddress + i, i);
                    }
                }
                free(buf);
            }
        }
        addr = (sentinel_addr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(proc);
    return SENTINEL_OK;
}
#else
int sentinel_scan_pattern(sentinel_pid_t pid, const char* pattern,
                          const sentinel_scan_config_t* config,
                          sentinel_scan_result_t* result) {
    (void)pid; (void)pattern; (void)config; (void)result;
    return SENTINEL_ERROR_UNSUPPORTED;
}
#endif

namespace sentinel { namespace memory {
Scanner::Scanner() : config_{}, result_{} { sentinel_scan_init_result(&result_, 64); }
Scanner::~Scanner() { sentinel_scan_free_result(&result_); }
void Scanner::set_target(sentinel_pid_t pid) { config_.target_pid = pid; }
void Scanner::set_range(sentinel_addr_t s, sentinel_addr_t e) { config_.start_address = s; config_.end_address = e; }
void Scanner::set_alignment(u32 a) { config_.alignment = a; }
int Scanner::scan(const char* pat) { return sentinel_scan_pattern(config_.target_pid, pat, &config_, &result_); }
usize Scanner::match_count() const { return result_.count; }
const sentinel_match_t* Scanner::matches() const { return result_.matches; }
sentinel_addr_t Scanner::first_match() const { return result_.count > 0 ? result_.matches[0].address : 0; }
void Scanner::reset() { result_.count = 0; }
}}

/*
 * Optimization: pre-filter using the first non-wildcard byte to skip
 * large swaths of non-matching memory. This significantly reduces false
 * positives and improves scan speed on binaries >100MB.
 */
static usize find_first_solid_byte(const u8* mask, usize len) {
    for (usize i = 0; i < len; i++) {
        if (mask[i] == 0xFF) return i;
    }
    return 0;
}

int sentinel_scan_bytes_optimized(const u8* haystack, usize haystack_size,
                                   const u8* needle, usize needle_size,
                                   const u8* mask, u32 alignment,
                                   sentinel_scan_result_t* result) {
    if (!haystack || !needle || !result) return SENTINEL_ERROR_INVALID_PARAMETER;
    if (needle_size == 0 || needle_size > haystack_size) return SENTINEL_OK;

    usize first_solid = mask ? find_first_solid_byte(mask, needle_size) : 0;
    u8 first_byte = needle[first_solid];
    usize step = (alignment > 0) ? alignment : 1;

    for (usize i = 0; i <= haystack_size - needle_size; i += step) {
        /* Quick reject on first solid byte */
        if (haystack[i + first_solid] != first_byte) continue;

        bool found = true;
        for (usize j = 0; j < needle_size; j++) {
            u8 m = mask ? mask[j] : 0xFF;
            if ((haystack[i+j] & m) != (needle[j] & m)) { found = false; break; }
        }
        if (found) {
            int rc = add_match(result, (sentinel_addr_t)(haystack + i), i);
            if (rc != SENTINEL_OK) return rc;
        }
    }
    return SENTINEL_OK;
}

/*
 * SSE4.2-optimized pattern scanner using PCMPESTRI for fast byte matching.
 * Falls back to the scalar implementation on non-SSE4.2 hardware.
 */
#if defined(__SSE4_2__) || defined(_MSC_VER)

#ifdef _MSC_VER
#include <intrin.h>
#include <nmmintrin.h>
#else
#include <x86intrin.h>
#endif

static bool has_sse42(void) {
    int info[4];
#ifdef _MSC_VER
    __cpuid(info, 1);
#else
    __cpuid(1, info[0], info[1], info[2], info[3]);
#endif
    return (info[2] & (1 << 20)) != 0;
}

int sentinel_scan_bytes_simd(const u8* haystack, usize haystack_size,
                              const u8* needle, usize needle_size,
                              const u8* mask, sentinel_scan_result_t* result) {
    if (!haystack || !needle || !result) return SENTINEL_ERROR_INVALID_PARAMETER;
    if (needle_size == 0 || needle_size > haystack_size) return SENTINEL_OK;
    if (needle_size > 16 || !has_sse42()) {
        /* Fall back to scalar for patterns > 16 bytes or no SSE4.2 */
        return sentinel_scan_bytes(haystack, haystack_size, needle, needle_size, mask, result);
    }

    /* Check if pattern has wildcards -- if so, use scalar */
    bool has_wildcards = false;
    if (mask) {
        for (usize i = 0; i < needle_size; i++) {
            if (mask[i] != 0xFF) { has_wildcards = true; break; }
        }
    }
    if (has_wildcards) {
        return sentinel_scan_bytes(haystack, haystack_size, needle, needle_size, mask, result);
    }

    /* Use _mm_cmpestrm for exact byte matching with SSE4.2 */
    __m128i pattern = _mm_loadu_si128((const __m128i*)needle);
    int pattern_len = (int)needle_size;

    for (usize i = 0; i + 16 <= haystack_size; i += 16) {
        __m128i chunk = _mm_loadu_si128((const __m128i*)(haystack + i));
        int idx = _mm_cmpestri(pattern, pattern_len, chunk, 16,
                               _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ORDERED |
                               _SIDD_LEAST_SIGNIFICANT);
        if (idx < 16) {
            /* Potential match at i + idx, verify full pattern */
            usize pos = i + idx;
            if (pos + needle_size <= haystack_size) {
                bool match = true;
                for (usize j = 0; j < needle_size; j++) {
                    if (haystack[pos + j] != needle[j]) { match = false; break; }
                }
                if (match) {
                    add_match(result, (sentinel_addr_t)(haystack + pos), pos);
                }
            }
            /* Continue scanning from idx+1 within this chunk */
            if (idx + 1 < 16) i -= (16 - idx - 1);
        }
    }

    /* Handle the tail that does not fit a full 16-byte chunk */
    usize tail_start = (haystack_size / 16) * 16;
    if (tail_start > 0) tail_start -= needle_size;
    for (usize i = tail_start; i + needle_size <= haystack_size; i++) {
        bool match = true;
        for (usize j = 0; j < needle_size; j++) {
            if (haystack[i + j] != needle[j]) { match = false; break; }
        }
        if (match) add_match(result, (sentinel_addr_t)(haystack + i), i);
    }

    return SENTINEL_OK;
}

#else
int sentinel_scan_bytes_simd(const u8* haystack, usize haystack_size,
                              const u8* needle, usize needle_size,
                              const u8* mask, sentinel_scan_result_t* result) {
    return sentinel_scan_bytes(haystack, haystack_size, needle, needle_size, mask, result);
}
#endif

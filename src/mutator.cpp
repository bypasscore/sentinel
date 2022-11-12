#include "sentinel/signature/mutator.h"
#include "sentinel/core/error.h"
#include "sentinel/utils/logger.h"
#include <cstring>
#include <cstdlib>

static u64 xorshift64(u64* state) {
    u64 x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* x86/x64 NOP variants for polymorphic NOP sleds */
static const u8 nop_1[] = { 0x90 };
static const u8 nop_2[] = { 0x66, 0x90 };
static const u8 nop_3[] = { 0x0F, 0x1F, 0x00 };
static const u8 nop_4[] = { 0x0F, 0x1F, 0x40, 0x00 };
static const u8 nop_5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

static const struct { const u8* bytes; usize len; } nop_variants[] = {
    { nop_1, 1 }, { nop_2, 2 }, { nop_3, 3 }, { nop_4, 4 }, { nop_5, 5 }
};

static int insert_nops(u8* code, usize code_size, usize buf_cap,
                        u64* rng, usize* new_size) {
    /* Insert random NOP variants at random positions */
    usize pos = (usize)(xorshift64(rng) % code_size);
    u32 variant = (u32)(xorshift64(rng) % 5);
    usize nop_len = nop_variants[variant].len;

    if (code_size + nop_len > buf_cap) return SENTINEL_ERROR_BUFFER_TOO_SMALL;

    /* Shift code to make room */
    memmove(code + pos + nop_len, code + pos, code_size - pos);
    memcpy(code + pos, nop_variants[variant].bytes, nop_len);
    *new_size = code_size + nop_len;
    return SENTINEL_OK;
}

static int insert_junk(u8* code, usize code_size, usize buf_cap,
                        u64* rng, usize* new_size) {
    /* Insert junk instructions that have no net effect */
    static const u8 junk_patterns[][4] = {
        { 0x50, 0x58, 0x00, 0x00 },         /* push rax; pop rax */
        { 0x51, 0x59, 0x00, 0x00 },         /* push rcx; pop rcx */
        { 0x87, 0xC0, 0x00, 0x00 },         /* xchg eax, eax */
        { 0x48, 0x87, 0xC9, 0x00 },         /* xchg rcx, rcx */
    };
    static const usize junk_sizes[] = { 2, 2, 2, 3 };

    u32 idx = (u32)(xorshift64(rng) % 4);
    usize jlen = junk_sizes[idx];
    usize pos = (usize)(xorshift64(rng) % code_size);

    if (code_size + jlen > buf_cap) return SENTINEL_ERROR_BUFFER_TOO_SMALL;
    memmove(code + pos + jlen, code + pos, code_size - pos);
    memcpy(code + pos, junk_patterns[idx], jlen);
    *new_size = code_size + jlen;
    return SENTINEL_OK;
}

int sentinel_mutate_buffer(u8* code, usize code_size, usize buf_cap,
                            const sentinel_mutator_config_t* config, usize* new_size) {
    if (!code || code_size == 0 || !new_size)
        return SENTINEL_ERROR_INVALID_PARAMETER;

    u32 passes = config ? config->mutation_passes : 1;
    u64 rng = config ? config->seed : 0x12345678ABCDEF01ULL;
    u32 types = config ? config->mutation_types : 0xFFFFFFFF;
    usize cur_size = code_size;

    for (u32 pass = 0; pass < passes; pass++) {
        u32 mutation = (u32)(xorshift64(&rng) % 3);
        int rc = SENTINEL_OK;

        if (mutation == 0 && (types & (1 << SENTINEL_MUTATE_NOP_INSERT))) {
            rc = insert_nops(code, cur_size, buf_cap, &rng, &cur_size);
        } else if (mutation == 1 && (types & (1 << SENTINEL_MUTATE_JUNK_INSERT))) {
            rc = insert_junk(code, cur_size, buf_cap, &rng, &cur_size);
        }
        /* SENTINEL_MUTATE_REGISTER_SWAP and others are more complex */

        if (rc != SENTINEL_OK) {
            *new_size = cur_size;
            return rc;
        }
    }

    *new_size = cur_size;
    return SENTINEL_OK;
}

int sentinel_mutate_pe_section(const char* filepath, const char* section_name,
                                const sentinel_mutator_config_t* config) {
    (void)filepath; (void)section_name; (void)config;
    SLOG_WARN("PE section mutation not yet implemented");
    return SENTINEL_ERROR_UNSUPPORTED;
}

#ifndef SENTINEL_SIGNATURE_MUTATOR_H
#define SENTINEL_SIGNATURE_MUTATOR_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum sentinel_mutation_type {
    SENTINEL_MUTATE_NOP_INSERT = 0,
    SENTINEL_MUTATE_REGISTER_SWAP,
    SENTINEL_MUTATE_INSTRUCTION_SUBSTITUTE,
    SENTINEL_MUTATE_JUNK_INSERT,
    SENTINEL_MUTATE_REORDER_BLOCKS
} sentinel_mutation_type_t;
typedef struct sentinel_mutator_config {
    u32 mutation_types;
    u32 mutation_passes;
    u32 junk_density;
    u64 seed;
} sentinel_mutator_config_t;
int sentinel_mutate_buffer(u8* code, usize code_size, usize buffer_capacity,
                            const sentinel_mutator_config_t* config, usize* new_size);
int sentinel_mutate_pe_section(const char* filepath, const char* section_name,
                                const sentinel_mutator_config_t* config);
#ifdef __cplusplus
}
#endif
#endif

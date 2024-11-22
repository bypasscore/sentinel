#ifndef SENTINEL_UTILS_CRYPTO_H
#define SENTINEL_UTILS_CRYPTO_H
#include "sentinel/core/types.h"
#ifdef __cplusplus
extern "C" {
#endif
void sentinel_xor_encrypt(u8* data, usize size, const u8* key, usize key_len);
void sentinel_xor_decrypt(u8* data, usize size, const u8* key, usize key_len);
void sentinel_rc4_init(u8 sbox[256], const u8* key, usize key_len);
void sentinel_rc4_crypt(u8 sbox[256], u8* data, usize size);
u32 sentinel_fnv1a_32(const u8* data, usize size);
u64 sentinel_fnv1a_64(const u8* data, usize size);
u32 sentinel_hash_string(const char* str);
u32 sentinel_hash_string_wide(const wchar_t* str);
#ifdef __cplusplus
}
#endif
#endif

#include "sentinel/utils/crypto.h"
#include <cstring>

void sentinel_xor_encrypt(u8* data, usize size, const u8* key, usize key_len) {
    if (!data || !key || key_len == 0) return;
    for (usize i = 0; i < size; i++)
        data[i] ^= key[i % key_len];
}

void sentinel_xor_decrypt(u8* data, usize size, const u8* key, usize key_len) {
    sentinel_xor_encrypt(data, size, key, key_len); /* XOR is symmetric */
}

void sentinel_rc4_init(u8 sbox[256], const u8* key, usize key_len) {
    for (int i = 0; i < 256; i++) sbox[i] = (u8)i;
    u8 j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + sbox[i] + key[i % key_len];
        u8 tmp = sbox[i]; sbox[i] = sbox[j]; sbox[j] = tmp;
    }
}

void sentinel_rc4_crypt(u8 sbox[256], u8* data, usize size) {
    u8 i = 0, j = 0;
    /* Make a working copy to not mutate the caller's sbox */
    u8 s[256];
    memcpy(s, sbox, 256);
    for (usize n = 0; n < size; n++) {
        i++; j += s[i];
        u8 tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[n] ^= s[(u8)(s[i] + s[j])];
    }
}

/* FNV-1a hash functions - useful for API hashing to avoid string detection */
u32 sentinel_fnv1a_32(const u8* data, usize size) {
    u32 hash = 0x811C9DC5;
    for (usize i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

u64 sentinel_fnv1a_64(const u8* data, usize size) {
    u64 hash = 0xCBF29CE484222325ULL;
    for (usize i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

/* Case-insensitive string hash (useful for API name resolution) */
u32 sentinel_hash_string(const char* str) {
    if (!str) return 0;
    u32 hash = 0x811C9DC5;
    while (*str) {
        char c = *str++;
        if (c >= 'A' && c <= 'Z') c += 32; /* tolower */
        hash ^= (u8)c;
        hash *= 0x01000193;
    }
    return hash;
}

u32 sentinel_hash_string_wide(const wchar_t* str) {
    if (!str) return 0;
    u32 hash = 0x811C9DC5;
    while (*str) {
        wchar_t c = *str++;
        if (c >= L'A' && c <= L'Z') c += 32;
        hash ^= (u8)(c & 0xFF);
        hash *= 0x01000193;
        hash ^= (u8)(c >> 8);
        hash *= 0x01000193;
    }
    return hash;
}

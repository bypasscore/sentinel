#include "sentinel/sentinel.h"
#include "sentinel/utils/pe_parser.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0, tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", #n);
#define PASS() tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(m) printf("FAIL (%s)\n", m); } while(0)

static void make_pe(u8* buf, usize sz, bool x64) {
    memset(buf, 0, sz);
    buf[0]=0x4D; buf[1]=0x5A;
    *(i32*)(buf+0x3C) = 0x80;
    *(u32*)(buf+0x80) = 0x00004550;
    u8* coff = buf+0x84;
    *(u16*)coff = x64 ? 0x8664 : 0x014C;
    *(u16*)(coff+2) = 1;
    *(u16*)(coff+16) = x64 ? 0xF0 : 0xE0;
    *(u16*)(coff+18) = 0x0002;
    u8* opt = coff+20;
    *(u16*)opt = x64 ? 0x020B : 0x010B;
    *(u32*)(opt+16) = 0x1000;
    if (x64) *(u64*)(opt+24) = 0x140000000ULL;
    else *(u32*)(opt+28) = 0x400000;
    *(u32*)(opt+56) = 0x10000;
    *(u32*)(opt+60) = 0x200;
    u8* sec = opt + (x64 ? 0xF0 : 0xE0);
    memcpy(sec, ".text", 5);
    *(u32*)(sec+8)=0x1000; *(u32*)(sec+12)=0x1000;
    *(u32*)(sec+16)=0x200; *(u32*)(sec+20)=0x200;
}

void test_pe64() {
    TEST(parse_pe64);
    u8 pe[1024]; make_pe(pe, sizeof(pe), true);
    sentinel_pe_info_t info = {};
    int rc = sentinel_pe_parse(pe, sizeof(pe), &info);
    if (rc!=SENTINEL_OK||!info.is_valid||!info.is_64bit||info.num_sections!=1) { FAIL("bad parse"); return; }
    PASS();
}

void test_pe32() {
    TEST(parse_pe32);
    u8 pe[1024]; make_pe(pe, sizeof(pe), false);
    sentinel_pe_info_t info = {};
    int rc = sentinel_pe_parse(pe, sizeof(pe), &info);
    if (rc!=SENTINEL_OK||!info.is_valid||info.is_64bit) { FAIL("bad parse"); return; }
    PASS();
}

void test_invalid() {
    TEST(parse_invalid);
    u8 data[64] = {};
    sentinel_pe_info_t info = {};
    if (sentinel_pe_parse(data, sizeof(data), &info)==SENTINEL_OK) { FAIL("should fail"); return; }
    PASS();
}

void test_rva() {
    TEST(rva_to_offset);
    u8 pe[1024]; make_pe(pe, sizeof(pe), true);
    sentinel_pe_info_t info = {};
    sentinel_pe_parse(pe, sizeof(pe), &info);
    if (sentinel_pe_rva_to_offset(&info, 0x1000) != 0x200) { FAIL("wrong offset"); return; }
    PASS();
}

void test_section() {
    TEST(find_section);
    u8 pe[1024]; make_pe(pe, sizeof(pe), true);
    sentinel_pe_info_t info = {};
    sentinel_pe_parse(pe, sizeof(pe), &info);
    sentinel_section_t sec = {};
    if (sentinel_pe_get_section(&info, ".text", &sec) != SENTINEL_OK) { FAIL("not found"); return; }
    if (sec.virtual_address != 0x1000) { FAIL("wrong VA"); return; }
    PASS();
}

int main() {
    printf("=== PE Parser Tests ===\n\n");
    sentinel_init();
    test_pe64(); test_pe32(); test_invalid(); test_rva(); test_section();
    sentinel_shutdown();
    printf("\n%d/%d passed.\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

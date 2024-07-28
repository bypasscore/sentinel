#include "sentinel/sentinel.h"
#include "sentinel/memory/scanner.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0, tests_passed = 0;
#define TEST(n) do { tests_run++; printf("  TEST: %s ... ", #n);
#define PASS() tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(m) printf("FAIL (%s)\n", m); } while(0)

void test_parse_ida_pattern() {
    TEST(parse_ida_pattern);
    u8 bytes[64], mask[64]; usize len = 0;
    int rc = sentinel_parse_ida_pattern("48 89 5C 24 ? 57", bytes, mask, &len);
    if (rc != SENTINEL_OK) { FAIL("parse failed"); return; }
    if (len != 6) { FAIL("wrong length"); return; }
    if (bytes[0] != 0x48 || mask[4] != 0x00 || mask[5] != 0xFF) { FAIL("wrong values"); return; }
    PASS();
}

void test_scan_bytes_basic() {
    TEST(scan_bytes_basic);
    u8 hay[] = { 0x00, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x00 };
    u8 needle[] = { 0x48, 0x89, 0x5C };
    sentinel_scan_result_t r = {};
    sentinel_scan_init_result(&r, 16);
    sentinel_scan_bytes(hay, sizeof(hay), needle, 3, nullptr, &r);
    if (r.count != 1 || r.matches[0].offset != 1) { FAIL("wrong result"); sentinel_scan_free_result(&r); return; }
    sentinel_scan_free_result(&r);
    PASS();
}

void test_scan_with_mask() {
    TEST(scan_with_mask);
    u8 hay[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x5C, 0x24, 0x20 };
    u8 needle[] = { 0x48, 0x89, 0x5C, 0x24, 0x00 };
    u8 mask[]   = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    sentinel_scan_result_t r = {};
    sentinel_scan_init_result(&r, 16);
    sentinel_scan_bytes(hay, sizeof(hay), needle, 5, mask, &r);
    if (r.count != 2) { FAIL("expected 2"); sentinel_scan_free_result(&r); return; }
    sentinel_scan_free_result(&r);
    PASS();
}

void test_scan_no_match() {
    TEST(scan_no_match);
    u8 hay[] = { 0x90, 0x90, 0x90 };
    u8 needle[] = { 0xCC, 0xCC };
    sentinel_scan_result_t r = {};
    sentinel_scan_init_result(&r, 16);
    sentinel_scan_bytes(hay, sizeof(hay), needle, 2, nullptr, &r);
    if (r.count != 0) { FAIL("expected 0"); sentinel_scan_free_result(&r); return; }
    sentinel_scan_free_result(&r);
    PASS();
}

int main() {
    printf("=== Scanner Tests ===\n\n");
    sentinel_init();
    test_parse_ida_pattern();
    test_scan_bytes_basic();
    test_scan_with_mask();
    test_scan_no_match();
    sentinel_shutdown();
    printf("\n%d/%d passed.\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

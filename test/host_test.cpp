// Host-side verification of miner_core.h (build: g++ -O2 -I../src host_test.cpp)
#include <stdio.h>
#include <stdlib.h>
#include "miner_core.h"

int main() {
    int fails = 0;

    // 1) plain SHA-256("abc")
    uint8_t d[32];
    sha256_bytes((const uint8_t*)"abc", 3, d);
    uint8_t exp_abc[32];
    hex2bin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp_abc, 32);
    if (memcmp(d, exp_abc, 32)) { puts("FAIL sha256(abc)"); fails++; } else puts("ok   sha256(abc)");

    // 2) Bitcoin genesis block header
    static Job j;
    hex2bin("010000000000000000000000000000000000000000000000000000000000000000000000"
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
            "29ab5f49ffff001d00000000", j.header, 80);
    job_prepare(j);
    diff_to_target(1.0, j.target);
    const uint32_t gn = 0x7c2bac1d;

    uint8_t dg[32];
    bool ok = job_check(j, gn, dg);
    uint8_t exp_hash[32];  // displayed (big-endian) form, reverse for digest order
    hex2bin("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", exp_hash, 32);
    bool match = true;
    for (int i = 0; i < 32; i++) if (dg[i] != exp_hash[31 - i]) match = false;
    printf("%s genesis hash via sha256d, share valid=%d\n", match ? "ok  " : "FAIL", ok);
    if (!match || !ok) fails++;

    uint32_t top = sw_top(j, gn);
    printf("%s genesis sw_top=0x%08x (expect 0)\n", top == 0 ? "ok  " : "FAIL", top);
    if (top != 0) fails++;

    // 3) random nonces: sw_top must equal the top limb of the reference hash
    srand(12345);
    int bad = 0;
    for (int i = 0; i < 20000; i++) {
        uint32_t n = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
        if (i % 7 == 0) { for (int k = 0; k < 80; k++) j.header[k] = rand(); job_prepare(j); }
        uint8_t dd[32];
        job_check(j, n, dd);
        uint32_t ref = load_le32(dd + 28);
        if (sw_top(j, n) != ref) bad++;
    }
    printf("%s 20000 random header/nonce comparisons, mismatches=%d\n", bad ? "FAIL" : "ok  ", bad);
    if (bad) fails++;

    // 4) diff_to_target sanity: diff 1 -> top limb 0x00000000FFFF0000 >> 32 = 0x00000000
    uint32_t t[8];
    diff_to_target(1.0, t);
    printf("target(d=1): [7]=%08x [6]=%08x\n", t[7], t[6]);
    if (t[7] != 0 || t[6] != 0xFFFF0000u) { puts("FAIL target"); fails++; }

    puts(fails ? "TESTS FAILED" : "ALL TESTS PASSED");
    return fails != 0;
}

// Off-target check of the *protocol* used by hwsha.h: a software model of the
// ESP32 SHA engine (TEXT regs, START/CONTINUE/LOAD) is driven with exactly the
// words that hw::prepare() produces, in the order one_hash() writes them.
// If the padding constants / word order were wrong, this would not match sw_top().
//   g++ -O2 -Istub -I../src hw_protocol_test.cpp
#include "hwsha.h"

struct FakeEngine {
    uint32_t text[16] = {0};
    uint32_t st[8];
    bool swap;   // true: registers hold big-endian SHA words; false: little-endian memory words
    void block(bool first) {
        uint32_t blk[16];
        for (int i = 0; i < 16; i++) blk[i] = swap ? text[i] : bswap32(text[i]);
        if (first) memcpy(st, SHA_IV, sizeof(st));
        sha256_transform(st, blk);
    }
    void load() { for (int i = 0; i < 8; i++) text[i] = swap ? st[i] : bswap32(st[i]); }
};

static uint32_t sim_one_hash(bool swap, const hw::HwJob& h, uint32_t n) {
    FakeEngine e; e.swap = swap;
    for (int i = 0; i < 16; i++) e.text[i] = h.b1[i];
    e.block(true);                                   // START
    e.text[0] = h.t[0]; e.text[1] = h.t[1]; e.text[2] = h.t[2];
    e.text[3] = swap ? bswap32(n) : n; e.text[4] = h.p4;
    for (int i = 5; i < 15; i++) e.text[i] = 0;
    e.text[15] = h.p15;
    e.block(false);                                  // CONTINUE
    e.load();                                        // LOAD -> hash1 in TEXT[0..7]
    e.text[8] = h.q8;
    for (int i = 9; i < 15; i++) e.text[i] = 0;
    e.text[15] = h.q15;
    e.block(true);                                   // START (new hash)
    e.load();
    return swap ? bswap32(e.text[7]) : e.text[7];
}

int main() {
    static Job j;
    hex2bin(hw::GENESIS_HDR_HEX, j.header, 80);
    job_prepare(j);
    int bad = 0;
    for (int swap = 0; swap < 2; swap++) {
        hw::HwJob h;
        hw::prepare(h, j, swap);
        for (uint32_t n = 0x7c2bac1du - 8; n < 0x7c2bac1du + 8; n++)
            if (sim_one_hash(swap, h, n) != sw_top(j, n)) bad++;
        printf("variant %s: %s\n", swap ? "big-endian regs" : "little-endian regs", bad ? "MISMATCH" : "matches software hash");
    }
    printf("genesis top limb via model = 0x%08x (expect 0)\n", [&] { hw::HwJob h; hw::prepare(h, j, false); return sim_one_hash(false, h, 0x7c2bac1du); }());
    return bad != 0;
}

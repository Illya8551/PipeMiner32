// =============================================================================
//  hwsha.h  -  ESP32 (classic) hardware SHA-256 engine driven directly
//
//  WHY THIS FILE EXISTS
//  --------------------
//  The classic ESP32 SHA peripheral cannot be loaded with an arbitrary
//  intermediate state (that "resume" feature only exists on S2/S3/C3), so the
//  midstate trick is NOT available in hardware: every nonce costs three HW
//  block operations (header block 1, header block 2, hash-of-hash).  Even so
//  one engine block takes a few hundred CPU cycles, versus ~3000 cycles for a
//  software block, so hardware is ~5-8x faster per core.
//
//  What we do to keep the overhead around the engine minimal:
//    * talk to the registers directly (no esp_sha_*, no locks, no mbedtls ctx)
//    * all words that go into TEXT are pre-built per job (HwJob)
//    * only H7 is read back (early reject) - one register read per nonce
//    * the whole loop lives in IRAM and compiles to l32i/s32i pairs
//
//  Register semantics (ESP32 TRM, "SHA accelerator"): 16 TEXT words hold one
//  64-byte block, START = first block (state := IV), CONTINUE = next block,
//  LOAD = copy internal state to TEXT[0..7], BUSY = 1 while working.
//  Word order inside TEXT is verified at boot (self-test) - two variants
//  (little-endian memory order, or classic big-endian words) are tried, and if
//  neither reproduces the software hash the firmware refuses to use hardware.
//
//  SAFETY: the boot sequence prints a line before every risky step and flushes
//  the UART, and every wait in the self-test is bounded. If the board still
//  resets, the LAST "[hw] ..." line in the log is the culprit.
// =============================================================================
#pragma once
#include <Arduino.h>
#include "miner_core.h"
#if __has_include("esp_private/periph_ctrl.h")
#include "esp_private/periph_ctrl.h"
#else
#include "driver/periph_ctrl.h"
#endif

// 0 (default): use only the documented DPORT address 0x3FF03000 (what ESP-IDF
// itself uses). 1: ALSO try the AHB alias 0x60003000 if DPORT fails. The alias
// is not needed for correctness and is the first suspect for a bus hang.
#ifndef HW_TRY_AHB_WINDOW
#define HW_TRY_AHB_WINDOW 0
#endif

namespace hw {

constexpr uint32_t DPORT_BASE = 0x3FF03000u;  // DR_REG_SHA_BASE
constexpr uint32_t AHB_BASE   = 0x60003000u;  // same registers through the AHB bus
constexpr uint32_t OFF_START  = 0x90 / 4;     // SHA_256_START_REG    (word index)
constexpr uint32_t OFF_CONT   = 0x94 / 4;     // SHA_256_CONTINUE_REG
constexpr uint32_t OFF_LOAD   = 0x98 / 4;     // SHA_256_LOAD_REG
constexpr uint32_t OFF_BUSY   = 0x9C / 4;     // SHA_256_BUSY_REG

// Everything that is constant for one job, already in the word order the engine
// expects (see 'swap').
struct HwJob {
    uint32_t b1[16];   // header block 1
    uint32_t t[3];     // header block 2, words 0..2 (merkle tail, ntime, nbits)
    uint32_t p4, p15;  // block 2 padding: 0x80.. marker and 640-bit length
    uint32_t q8, q15;  // hash-of-hash padding: 0x80.. marker and 256-bit length
    bool     swap;
};

static void prepare(HwJob& h, const Job& j, bool swap) {
    h.swap = swap;
    for (int i = 0; i < 16; i++) h.b1[i] = swap ? bswap32(j.raw[i]) : j.raw[i];
    for (int i = 0; i < 3; i++) h.t[i] = swap ? bswap32(j.raw[16 + i]) : j.raw[16 + i];
    h.p4  = swap ? 0x80000000u : 0x00000080u;
    h.q8  = h.p4;
    h.p15 = swap ? 640u : 0x80020000u;   // 640 bits, as the last 8 bytes (BE) of the block
    h.q15 = swap ? 256u : 0x00010000u;   // 256 bits
}

// Wait until the engine is idle. CHECK=true (self-test only): give up after a
// bounded number of polls instead of spinning forever. CHECK=false (hot path):
// plain spin, zero overhead.
template <bool CHECK>
FORCE_INLINE bool wait_idle(volatile uint32_t* BUSY) {
    if (CHECK) {
        uint32_t spins = 200000;
        while (*BUSY) { if (--spins == 0) return false; }
        return true;
    }
    while (*BUSY) {}
    return true;
}

// One full Bitcoin hash (double SHA-256 of the 80-byte header) for `n`.
// Returns the top 32 bits of the hash as a number (= H7 byte-swapped).
// With CHECK=true a stuck engine makes it return 0xFFFFFFFF.
template <bool SWAP, bool CHECK = false>
FORCE_INLINE uint32_t one_hash(volatile uint32_t* T, const HwJob& h, uint32_t n) {
    volatile uint32_t* const START = T + OFF_START;
    volatile uint32_t* const CONT  = T + OFF_CONT;
    volatile uint32_t* const LOAD  = T + OFF_LOAD;
    volatile uint32_t* const BUSY  = T + OFF_BUSY;

    // ---- block 1 of the header (identical for every nonce, but the engine
    //      cannot keep a midstate, so it is hashed again) -------------------
#pragma GCC unroll 16
    for (int i = 0; i < 16; i++) T[i] = h.b1[i];
    *START = 1;
    if (!wait_idle<CHECK>(BUSY)) return 0xFFFFFFFFu;

    // ---- block 2: merkle tail | ntime | nbits | nonce | padding | length ---
    T[0] = h.t[0]; T[1] = h.t[1]; T[2] = h.t[2];
    T[3] = SWAP ? bswap32(n) : n;
    T[4] = h.p4;
#pragma GCC unroll 10
    for (int i = 5; i < 15; i++) T[i] = 0;
    T[15] = h.p15;
    *CONT = 1;
    if (!wait_idle<CHECK>(BUSY)) return 0xFFFFFFFFu;

    // ---- hash #1 -> TEXT[0..7]; it is the message of hash #2 -------------
    *LOAD = 1;
    if (!wait_idle<CHECK>(BUSY)) return 0xFFFFFFFFu;
    T[8] = h.q8;
#pragma GCC unroll 6
    for (int i = 9; i < 15; i++) T[i] = 0;
    T[15] = h.q15;
    *START = 1;                    // new hash: state := IV
    if (!wait_idle<CHECK>(BUSY)) return 0xFFFFFFFFu;

    // ---- hash #2: read back only H7 (early reject) ------------------------
    *LOAD = 1;
    if (!wait_idle<CHECK>(BUSY)) return 0xFFFFFFFFu;
    uint32_t top = T[7];
    return SWAP ? bswap32(top) : top;
}

// Hot loop: tests `count` nonces starting at `start`. Nonces whose top word is
// <= tgt_top are stored in cands[] (caller verifies them with the slow, exact
// check). Stops early if cands[] is full. *done = nonces actually processed.
template <bool SWAP>
static __attribute__((noinline)) IRAM_ATTR uint32_t search(volatile uint32_t* T, const HwJob& h,
                                                           uint32_t start, uint32_t count,
                                                           uint32_t tgt_top, uint32_t* cands,
                                                           uint32_t maxc, uint32_t* done) {
    uint32_t nc = 0, i = 0;
    for (; i < count; i++) {
        uint32_t n = start + i;
        uint32_t top = one_hash<SWAP, false>(T, h, n);
        if (top <= tgt_top) {
            cands[nc++] = n;
            if (nc >= maxc) { i++; break; }
        }
    }
    *done = i;
    return nc;
}

// ---- pipelined ("overlapped") search ----------------------------------------
// Measured on a real board: the engine alone is ~806 kH/s-equivalent and the TEXT
// register writes alone ~862, but the plain loop does them one after the other
// (-> ~394). Here the writes for the NEXT block are issued while the engine is
// still busy with the CURRENT one, so the two overlap.
//
// This relies on the engine having consumed message word i a few cycles after it
// is started (roughly one word per 80 MHz engine cycle, while we write one word
// per ~6 CPU cycles = 2 engine cycles, in ascending order, after a short delay).
// That is NOT documented by Espressif, so it is only enabled if a boot-time test
// against the software hash (2048 nonces, run from IRAM at real speed) passes.
// Delays only ever make writes LATER, which is the safe direction.
constexpr int OV_A_DELAY = 12;   // nops after START of header block 1

template <int N>
FORCE_INLINE void nops() {
#pragma GCC unroll 128
    for (int i = 0; i < N; i++) __asm__ __volatile__("nop");
}

// TOPS=true: store every top word in tops[] (self-test), CHECK=true: bounded waits.
// TOPS=false: store nonces whose top word <= tgt_top in cands[] (mining).
template <bool SWAP, bool CHECK, bool TOPS, int DB, int DC>
FORCE_INLINE bool ov_body(volatile uint32_t* T, const HwJob& h, uint32_t start, uint32_t count,
                          uint32_t tgt_top, uint32_t* cands, uint32_t maxc, uint32_t* tops,
                          uint32_t* ncand, uint32_t* done) {
    volatile uint32_t* const START = T + OFF_START;
    volatile uint32_t* const CONT  = T + OFF_CONT;
    volatile uint32_t* const LOAD  = T + OFF_LOAD;
    volatile uint32_t* const BUSY  = T + OFF_BUSY;
    uint32_t nc = 0, i = 0;

    // words 8..15 of header block 1 are written while hash #2 runs (see below);
    // the very first iteration needs them in place already
#pragma GCC unroll 8
    for (int k = 8; k < 16; k++) T[k] = h.b1[k];

    for (; i < count; i++) {
        const uint32_t n  = start + i;
        const uint32_t nw = SWAP ? bswap32(n) : n;

        // ---- header block 1: words 0..7 now, 8..15 are already there --------
#pragma GCC unroll 8
        for (int k = 0; k < 8; k++) T[k] = h.b1[k];
        *START = 1;
        nops<OV_A_DELAY>();
        // engine is busy: build header block 2 in TEXT behind it
        T[0] = h.t[0]; T[1] = h.t[1]; T[2] = h.t[2]; T[3] = nw; T[4] = h.p4;
#pragma GCC unroll 10
        for (int k = 5; k < 15; k++) T[k] = 0;
        T[15] = h.p15;
        if (!wait_idle<CHECK>(BUSY)) { *done = i; *ncand = nc; return false; }

        // ---- header block 2 ---------------------------------------------------
        *CONT = 1;
        nops<DB>();
        T[8] = h.q8; T[15] = h.q15;           // hash #2 padding (T[9..14] are already 0)
        if (!wait_idle<CHECK>(BUSY)) { *done = i; *ncand = nc; return false; }

        // ---- hash #1 -> TEXT[0..7] = message of hash #2 -------------------------
        *LOAD = 1;
        if (!wait_idle<CHECK>(BUSY)) { *done = i; *ncand = nc; return false; }
        *START = 1;
        nops<DC>();
        // engine is busy with hash #2: prepare words 8..15 of the NEXT header block 1
#pragma GCC unroll 8
        for (int k = 8; k < 16; k++) T[k] = h.b1[k];
        if (!wait_idle<CHECK>(BUSY)) { *done = i; *ncand = nc; return false; }

        // ---- hash #2: read back H7 only ---------------------------------------
        *LOAD = 1;
        if (!wait_idle<CHECK>(BUSY)) { *done = i; *ncand = nc; return false; }
        uint32_t top = T[7];
        top = SWAP ? bswap32(top) : top;
        if (TOPS) {
            tops[i] = top;
        } else if (top <= tgt_top) {
            cands[nc++] = n;
            if (nc >= maxc) { i++; break; }
        }
    }
    *done = i; *ncand = nc;
    return true;
}

template <bool SWAP, int DB, int DC>
static __attribute__((noinline)) IRAM_ATTR uint32_t ov_search(volatile uint32_t* T, const HwJob& h,
                                                              uint32_t start, uint32_t count,
                                                              uint32_t tgt_top, uint32_t* cands,
                                                              uint32_t maxc, uint32_t* done) {
    uint32_t nc = 0;
    ov_body<SWAP, false, false, DB, DC>(T, h, start, count, tgt_top, cands, maxc, nullptr, &nc, done);
    return nc;
}

// self-test version: bounded waits, returns all top words
template <bool SWAP, int DB, int DC>
static __attribute__((noinline)) IRAM_ATTR bool ov_tops(volatile uint32_t* T, const HwJob& h,
                                                        uint32_t start, uint32_t count,
                                                        uint32_t* tops) {
    uint32_t nc = 0, done = 0;
    bool ok = ov_body<SWAP, true, true, DB, DC>(T, h, start, count, 0, nullptr, 0, tops, &nc, &done);
    return ok && done == count;
}

typedef uint32_t (*OvSearchFn)(volatile uint32_t*, const HwJob&, uint32_t, uint32_t, uint32_t,
                               uint32_t*, uint32_t, uint32_t*);
typedef bool (*OvTopsFn)(volatile uint32_t*, const HwJob&, uint32_t, uint32_t, uint32_t*);

// The B/C delays are the knob: the shorter, the faster, until the writes start
// to overtake the engine. They are tried from long to short at boot; the first
// failing preset ends the search and a preset two steps SAFER than it is used.
struct OvPreset { int b, c; OvSearchFn search; OvTopsFn tops; };

#define OV_PRESET(SW, B, C) { B, C, ov_search<SW, B, C>, ov_tops<SW, B, C> }
static const OvPreset OV_BE[] = {            // big-endian word order (classic ESP32)
    OV_PRESET(true, 90, 90), OV_PRESET(true, 64, 64), OV_PRESET(true, 48, 48),
    OV_PRESET(true, 36, 36), OV_PRESET(true, 28, 28), OV_PRESET(true, 20, 20),
    OV_PRESET(true, 14, 14), OV_PRESET(true, 8, 8),
};
static const OvPreset OV_LE[] = {            // little-endian order: just the safe default
    OV_PRESET(false, 90, 90),
};

// ---- diagnostics: where does the time go? ---------------------------------
// engine_only: the same 5 engine operations as one_hash (3 blocks + 2 LOADs) but
// with NO TEXT register traffic. If this is already about as slow as the real
// miner, the engine itself is the limit and no rewrite can help.
static __attribute__((noinline)) IRAM_ATTR void engine_only(volatile uint32_t* T, uint32_t n) {
    volatile uint32_t* const START = T + OFF_START;
    volatile uint32_t* const CONT  = T + OFF_CONT;
    volatile uint32_t* const LOAD  = T + OFF_LOAD;
    volatile uint32_t* const BUSY  = T + OFF_BUSY;
    for (uint32_t i = 0; i < n; i++) {
        *START = 1; while (*BUSY) {}
        *CONT  = 1; while (*BUSY) {}
        *LOAD  = 1; while (*BUSY) {}
        *START = 1; while (*BUSY) {}
        *LOAD  = 1; while (*BUSY) {}
    }
}
// writes_only: the ~45 TEXT register writes + 1 read one hash needs, no engine ops.
static __attribute__((noinline)) IRAM_ATTR uint32_t writes_only(volatile uint32_t* T, uint32_t n) {
    uint32_t acc = 0;
    for (uint32_t i = 0; i < n; i++) {
#pragma GCC unroll 45
        for (int k = 0; k < 45; k++) T[k & 15] = i + k;
        acc += T[7];
    }
    return acc;
}

// ---- runtime selection -----------------------------------------------------
struct Engine {
    volatile uint32_t* T = nullptr;
    bool swap = false;
    bool ok = false;
    bool ov_ok = false;    // pipelined mode passed its self-test
    bool use_ov = false;   // pipelined mode currently selected
    OvSearchFn ov_search_fn = nullptr;
    int ov_b = 0, ov_c = 0;
};
static Engine eng;

static const char GENESIS_HDR_HEX[] =
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49ffff001d00000000";

// Compare the hardware result with the software reference for 16 nonces around
// the genesis nonce (one of them is a real, valid Bitcoin hash).
static bool selftest(volatile uint32_t* T, bool swap) {
    static Job j;
    static HwJob h;
    hex2bin(GENESIS_HDR_HEX, j.header, 80);
    job_prepare(j);
    prepare(h, j, swap);
    const uint32_t gn = 0x7c2bac1du;
    for (uint32_t n = gn - 8; n < gn + 8; n++) {
        uint32_t hwtop = swap ? one_hash<true, true>(T, h, n) : one_hash<false, true>(T, h, n);
        if (hwtop != sw_top(j, n)) return false;
    }
    return true;
}

// Same check for the pipelined loop: `chunks` x 256 consecutive nonces around the
// genesis nonce, every top word compared with the software result.
static bool selftest_ov(volatile uint32_t* T, bool swap, OvTopsFn fn, uint32_t chunks) {
    static Job j;
    static HwJob h;
    static uint32_t tops[256];
    hex2bin(GENESIS_HDR_HEX, j.header, 80);
    job_prepare(j);
    prepare(h, j, swap);
    const uint32_t base = 0x7c2bac1du - 128;
    for (uint32_t chunk = 0; chunk < chunks; chunk++) {
        uint32_t s = base + chunk * 256;
        if (!fn(T, h, s, 256, tops)) return false;
        for (uint32_t k = 0; k < 256; k++)
            if (tops[k] != sw_top(j, s + k)) return false;
    }
    return true;
}

// Pick the fastest pipelined preset that passes with a safety margin.
static void tune_ov(volatile uint32_t* T, bool swap) {
    const OvPreset* tbl = swap ? OV_BE : OV_LE;
    const int n = swap ? (int)(sizeof(OV_BE) / sizeof(OV_BE[0])) : (int)(sizeof(OV_LE) / sizeof(OV_LE[0]));
    int first_fail = -1;
    for (int i = 0; i < n; i++) {
        Serial.printf("[hw] pipelined test, delays B=%d C=%d ... ", tbl[i].b, tbl[i].c); Serial.flush();
        bool ok = selftest_ov(T, swap, tbl[i].tops, 32);   // 8192 nonces
        Serial.println(ok ? "OK" : "FAIL"); Serial.flush();
        if (!ok) { first_fail = i; break; }
    }
    int pick;
    if (first_fail == 0) { eng.ov_ok = false; return; }        // not even the safest preset works
    if (first_fail < 0) pick = n > 1 ? n - 2 : 0;              // never failed: one step of margin
    else pick = first_fail >= 2 ? first_fail - 2 : 0;          // two steps safer than the first failure
    eng.ov_ok = true;
    eng.ov_search_fn = tbl[pick].search;
    eng.ov_b = tbl[pick].b; eng.ov_c = tbl[pick].c;
    Serial.printf("[hw] pipelined mode: using delays B=%d C=%d\n", eng.ov_b, eng.ov_c); Serial.flush();
}

// Enable the peripheral and find a register window + word order that works.
// Every step prints (and flushes) BEFORE it runs, so after a hang/reset the
// last line of the log names the step that killed the board.
static bool init() {
    Serial.println("[hw] step 1: enabling SHA peripheral clock"); Serial.flush();
    periph_module_enable(PERIPH_SHA_MODULE);
    Serial.println("[hw] step 2: clock enabled"); Serial.flush();

    uint32_t bases[2];
    int nb = 0;
    bases[nb++] = DPORT_BASE;
#if HW_TRY_AHB_WINDOW
    bases[nb++] = AHB_BASE;
#endif
    for (int b = 0; b < nb; b++) {
        volatile uint32_t* T = (volatile uint32_t*)(uintptr_t)bases[b];
        const char* name = (bases[b] == DPORT_BASE) ? "DPORT" : "AHB";
        for (int s = 0; s < 2; s++) {
            Serial.printf("[hw] step 3: self-test, %s window 0x%08x, %s word order\n",
                          name, (unsigned)bases[b], s ? "big-endian" : "little-endian");
            Serial.flush();
            if (selftest(T, s != 0)) {
                eng.T = T; eng.swap = (s != 0); eng.ok = true;
                Serial.printf("[hw] SHA engine OK (%s window, %s word order)\n",
                              name, s ? "big-endian" : "little-endian");
                Serial.flush();
                Serial.println("[hw] tuning pipelined mode"); Serial.flush();
                tune_ov(T, s != 0);
                if (!eng.ov_ok) Serial.println("[hw] pipelined mode FAILED -> plain mode only");
                Serial.flush();
                return true;
            }
            Serial.println("[hw]   -> mismatch / engine stuck"); Serial.flush();
        }
    }
    Serial.println("[hw] SHA engine self-test FAILED -> software only");
    Serial.flush();
    return false;
}

// Convenience wrapper used by the worker.
static inline uint32_t run(const HwJob& h, uint32_t start, uint32_t count, uint32_t tgt_top,
                           uint32_t* cands, uint32_t maxc, uint32_t* done) {
    if (eng.use_ov)
        return eng.ov_search_fn(eng.T, h, start, count, tgt_top, cands, maxc, done);
    return eng.swap ? search<true>(eng.T, h, start, count, tgt_top, cands, maxc, done)
                    : search<false>(eng.T, h, start, count, tgt_top, cands, maxc, done);
}

}  // namespace hw

// =============================================================================
//  miner_core.h  -  SHA-256d core for Bitcoin block-header mining
//
//  Portable C++ (host-testable). Contains:
//    * generic SHA-256 (used for coinbase / merkle tree / verification)
//    * Job: everything that is constant for one (job, extranonce2) pair
//    * sw_top(): the hot software hash path (midstate + precomputed rounds +
//                early reject) -> returns the top 32 bits of the final hash
//
//  Byte-order conventions used everywhere in this file:
//    "BE word"  = word as SHA-256 sees it (big-endian interpretation of bytes)
//    "raw word" = little-endian load of the header bytes (what ESP32 HW SHA
//                 wants in its TEXT registers)
// =============================================================================
#pragma once
#include <stdint.h>
#include <string.h>
#include <math.h>

#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#ifndef DRAM_ATTR
#define DRAM_ATTR
#endif

#define FORCE_INLINE static inline __attribute__((always_inline))

static inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

DRAM_ATTR static const uint32_t SHA_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

DRAM_ATTR static const uint32_t SHA_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// ---- round primitives -------------------------------------------------------
// GCC's Xtensa backend turns (x>>n)|(x<<(32-n)) into "ssai n; src d,x,x"
// (funnel-shift rotate), so no hand-written asm is needed for the rotates.
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define S1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define s0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define s1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

// One round. Instead of shifting 8 registers every round we rotate the *names*
// (see RND8) -> zero register moves.  New e is stored in d, new a in h.
#define RNDX(X, a, b, c, d, e, f, g, h, i)                                   \
    {                                                                        \
        uint32_t t1 = h + S1(e) + CH(e, f, g) + SHA_K[i] + X[i];             \
        d += t1;                                                             \
        h = t1 + S0(a) + MAJ(a, b, c);                                       \
    }

#define RND8(X, i)                                                           \
    RNDX(X, a, b, c, d, e, f, g, h, (i) + 0);                                \
    RNDX(X, h, a, b, c, d, e, f, g, (i) + 1);                                \
    RNDX(X, g, h, a, b, c, d, e, f, (i) + 2);                                \
    RNDX(X, f, g, h, a, b, c, d, e, (i) + 3);                                \
    RNDX(X, e, f, g, h, a, b, c, d, (i) + 4);                                \
    RNDX(X, d, e, f, g, h, a, b, c, (i) + 5);                                \
    RNDX(X, c, d, e, f, g, h, a, b, (i) + 6);                                \
    RNDX(X, b, c, d, e, f, g, h, a, (i) + 7);

// ---- generic SHA-256 (not hot) ---------------------------------------------
static void sha256_transform(uint32_t st[8], const uint32_t in[16]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) W[i] = in[i];
    for (int i = 16; i < 64; i++) W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i += 8) { RND8(W, i) }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static inline uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint32_t load_le32(const uint8_t* p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}
static inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

// One-shot SHA-256 of an arbitrary buffer; out = 32 digest bytes.
static void sha256_bytes(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t st[8], blk[16];
    memcpy(st, SHA_IV, sizeof(st));
    size_t full = len / 64;
    for (size_t n = 0; n < full; n++, data += 64) {
        for (int j = 0; j < 16; j++) blk[j] = load_be32(data + 4 * j);
        sha256_transform(st, blk);
    }
    uint8_t buf[128] = {0};
    size_t rem = len % 64;
    memcpy(buf, data, rem);
    buf[rem] = 0x80;
    size_t total = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t o = 0; o < total; o += 64) {
        for (int j = 0; j < 16; j++) blk[j] = load_be32(buf + o + 4 * j);
        sha256_transform(st, blk);
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = st[i] >> 24; out[4 * i + 1] = st[i] >> 16;
        out[4 * i + 2] = st[i] >> 8; out[4 * i + 3] = st[i];
    }
}
static void sha256d(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t t[32];
    sha256_bytes(data, len, t);
    sha256_bytes(t, 32, out);
}

// ---- hex helpers --------------------------------------------------------------
static inline int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
// Decode an even-length hex string. Returns number of bytes, or -1 on error /
// overflow of maxlen.
static int hex2bin(const char* hex, uint8_t* out, size_t maxlen) {
    if (!hex) return -1;
    size_t n = strlen(hex);
    if (n & 1 || n / 2 > maxlen) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int h = hexnib(hex[2 * i]), l = hexnib(hex[2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return (int)(n / 2);
}
static void bin2hex(const uint8_t* in, size_t n, char* out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 15]; }
    out[2 * n] = 0;
}

// ---- Job --------------------------------------------------------------------
struct Job {
    char     id[48];        // stratum job_id
    char     en2[20];       // extranonce2 (hex string, as submitted)
    char     ntime[12];     // ntime (hex string, as submitted)
    uint8_t  header[80];    // block header template (nonce = 0)
    uint32_t raw[19];       // header words 0..18, little-endian load (HW SHA input)
    uint32_t mid[8];        // midstate after header[0..63]
    uint32_t pre[8];        // state after rounds 0..2 of block 2 (nonce independent)
    uint32_t w[3];          // BE words 16..18 of header (merkle tail, ntime, nbits)
    uint32_t w16, w17;      // schedule words that do not depend on the nonce
    uint32_t target[8];     // 256-bit share target, little-endian limbs, [7] = MSW
};

// Share target for pool difficulty d:  (0xFFFF << 208) / d
static void diff_to_target(double d, uint32_t t[8]) {
    if (d < 1e-6) d = 1e-6;
    double v = 65535.0 * ldexp(1.0, 208) / d;
    for (int i = 7; i >= 0; i--) {
        double w = floor(ldexp(v, -32 * i));
        if (w > 4294967295.0) w = 4294967295.0;
        t[i] = (uint32_t)w;
        v -= ldexp(w, 32 * i);
        if (v < 0) v = 0;
    }
}

// Precompute everything nonce-independent. j.header must be filled.
static void job_prepare(Job& j) {
    memcpy(j.raw, j.header, 76);          // little-endian host: raw words
    uint32_t blk[16];
    for (int i = 0; i < 16; i++) blk[i] = bswap32(j.raw[i]);
    memcpy(j.mid, SHA_IV, sizeof(j.mid));
    sha256_transform(j.mid, blk);         // midstate: header bytes 0..63

    for (int i = 0; i < 3; i++) j.w[i] = bswap32(j.raw[16 + i]);

    // block 2 = [w0 w1 w2 NONCE 0x80000000 0*10 640]
    uint32_t W[18] = {j.w[0], j.w[1], j.w[2], 0, 0x80000000u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640, 0, 0};
    j.w16 = s1(W[14]) + W[9]  + s0(W[1]) + W[0];
    j.w17 = s1(W[15]) + W[10] + s0(W[2]) + W[1];

    uint32_t a = j.mid[0], b = j.mid[1], c = j.mid[2], d = j.mid[3];
    uint32_t e = j.mid[4], f = j.mid[5], g = j.mid[6], h = j.mid[7];
    RNDX(W, a, b, c, d, e, f, g, h, 0);
    RNDX(W, h, a, b, c, d, e, f, g, 1);
    RNDX(W, g, h, a, b, c, d, e, f, 2);
    // logical state A..H is now held in variables f,g,h,a,b,c,d,e
    j.pre[0] = f; j.pre[1] = g; j.pre[2] = h; j.pre[3] = a;
    j.pre[4] = b; j.pre[5] = c; j.pre[6] = d; j.pre[7] = e;
}

// ---- hot path ----------------------------------------------------------------
// Returns the top 32 bits of the Bitcoin hash (as a number) for `nonce`.
// Valid share  <=>  top <= target[7]  (+ full compare when equal/rare).
//
// Savings vs. a naive double SHA-256:
//   * block 1 of the header is never recomputed (midstate)
//   * rounds 0..2 of block 2 and W16/W17 are precomputed per job
//   * second hash: padding words are constants, message schedule shortened
//   * EARLY REJECT: the final word H7 = IV7 + e(after round 60) so rounds
//     61..63 (+ the dead 'a' chain in 57..60) of the 2nd compression are
//     never executed; the compiler removes them as dead code.
FORCE_INLINE uint32_t sw_top(const Job& j, uint32_t nonce) {
    uint32_t W[64];
    W[0] = j.w[0]; W[1] = j.w[1]; W[2] = j.w[2]; W[3] = bswap32(nonce);
    W[4] = 0x80000000u;
    for (int i = 5; i < 15; i++) W[i] = 0;
    W[15] = 640;
    W[16] = j.w16; W[17] = j.w17;
    for (int i = 18; i < 64; i++) W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

    // resume after round 2: logical A..H live in f,g,h,a,b,c,d,e
    uint32_t f = j.pre[0], g = j.pre[1], h = j.pre[2], a = j.pre[3];
    uint32_t b = j.pre[4], c = j.pre[5], d = j.pre[6], e = j.pre[7];
    RNDX(W, f, g, h, a, b, c, d, e, 3);
    RNDX(W, e, f, g, h, a, b, c, d, 4);
    RNDX(W, d, e, f, g, h, a, b, c, 5);
    RNDX(W, c, d, e, f, g, h, a, b, 6);
    RNDX(W, b, c, d, e, f, g, h, a, 7);
    for (int i = 8; i < 64; i += 8) { RND8(W, i) }

    // second hash: message = hash1 || padding(256 bits)
    uint32_t V[64];
    V[0] = j.mid[0] + a; V[1] = j.mid[1] + b; V[2] = j.mid[2] + c; V[3] = j.mid[3] + d;
    V[4] = j.mid[4] + e; V[5] = j.mid[5] + f; V[6] = j.mid[6] + g; V[7] = j.mid[7] + h;
    V[8] = 0x80000000u;
    for (int i = 9; i < 15; i++) V[i] = 0;
    V[15] = 256;
    for (int i = 16; i < 61; i++) V[i] = s1(V[i - 2]) + V[i - 7] + s0(V[i - 15]) + V[i - 16];

    a = SHA_IV[0]; b = SHA_IV[1]; c = SHA_IV[2]; d = SHA_IV[3];
    e = SHA_IV[4]; f = SHA_IV[5]; g = SHA_IV[6]; h = SHA_IV[7];
    for (int i = 0; i < 56; i += 8) { RND8(V, i) }
    RNDX(V, a, b, c, d, e, f, g, h, 56);
    RNDX(V, h, a, b, c, d, e, f, g, 57);
    RNDX(V, g, h, a, b, c, d, e, f, 58);
    RNDX(V, f, g, h, a, b, c, d, e, 59);
    RNDX(V, e, f, g, h, a, b, c, d, 60);   // new e (= H7 - IV7) is now in 'h'
    return bswap32(SHA_IV[7] + h);
}

// Slow, obviously-correct check (also used to verify every candidate).
// Fills digest (32 bytes) and returns true if hash <= target.
static bool job_check(const Job& j, uint32_t nonce, uint8_t digest[32]) {
    uint8_t hdr[80];
    memcpy(hdr, j.header, 76);
    store_le32(hdr + 76, nonce);
    sha256d(hdr, 80, digest);
    for (int k = 7; k >= 0; k--) {           // digest is a little-endian number
        uint32_t hv = load_le32(digest + 4 * k);
        if (hv < j.target[k]) return true;
        if (hv > j.target[k]) return false;
    }
    return true;
}

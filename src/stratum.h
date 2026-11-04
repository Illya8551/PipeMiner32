// =============================================================================
//  stratum.h  -  Stratum v1 client + state shared with the mining workers
// =============================================================================
#pragma once
#include <Arduino.h>
#include "miner_core.h"

constexpr size_t CB_MAX     = 512;   // max bytes of coinb1 / coinb2
constexpr size_t BRANCH_MAX = 16;    // max merkle branches
constexpr int    NUM_WORKER_SLOTS = 4;  // en2 = counter * 4 + worker_id (distinct work per worker)

// One mining.notify, already converted to the byte order of the block header.
struct Notify {
    char     job_id[48];
    char     ntime_hex[12];
    uint8_t  version[4];       // header byte order
    uint8_t  prevhash[32];     // header byte order (stratum word-swap undone)
    uint8_t  nbits[4];
    uint8_t  ntime[4];
    uint8_t  cb1[CB_MAX];  uint16_t cb1_len;
    uint8_t  cb2[CB_MAX];  uint16_t cb2_len;
    uint8_t  branch[BRANCH_MAX][32]; uint8_t branch_cnt;
    bool     clean;
};

struct Share {
    char     job_id[48];
    char     en2[20];
    char     ntime[12];
    uint32_t nonce;
    double   diff;             // pool difficulty the share was found at
};

struct SharedState {
    SemaphoreHandle_t mtx;
    Notify   notify;
    uint8_t  en1[8];  uint8_t en1_len;  uint8_t en2_size;
    double   pool_diff;
    volatile uint32_t job_gen;     // ++ on every mining.notify
    volatile uint32_t diff_gen;    // ++ on every mining.set_difficulty
    volatile bool     have_job;
    // statistics
    volatile uint64_t hashes_hw, hashes_sw;
    volatile uint32_t accepted, rejected, submitted;
    double   acc_diff_sum;         // sum of the difficulties of accepted shares
    double   best_diff;            // best share difficulty seen locally
    uint32_t t_authorized_ms;      // millis() when the pool accepted our login
};
extern SharedState G;

void stratum_init();
void stratum_task(void*);

// Called by workers. Thread-safe.
bool stratum_push_share(const Share& s);

// Build the work for one worker from the latest notify. Returns false if there
// is no job yet. gen_out / dgen_out receive the generations the job belongs to.
bool build_job(Job& j, int worker, uint32_t en2ctr, uint32_t* gen_out, uint32_t* dgen_out);
// Refresh only the share target (pool difficulty changed).
void refresh_target(Job& j, uint32_t* dgen_out);
// Difficulty of a 256-bit little-endian hash value (digest bytes).
double digest_to_diff(const uint8_t digest[32]);

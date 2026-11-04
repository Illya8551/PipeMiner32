// =============================================================================
//  config.h  -  edit this file before flashing
// =============================================================================
#pragma once
#include <stdint.h>

// ---- Credentials ----------------------------------------------------------------
// Put your own values into src/secrets.h (copy secrets.example.h). That file is
// git-ignored, so your WiFi password and payout address stay off GitHub.
// WIFI_SSID / WIFI_PASS: 2.4 GHz WiFi only. POOL_USER: your own bitcoin address,
// optionally followed by ".workername".
#if __has_include("secrets.h")
#include "secrets.h"
#else
#define WIFI_SSID  "your-wifi-name"
#define WIFI_PASS  "your-wifi-password"
#define POOL_USER  "bc1q-your-bitcoin-address.worker"
#endif

// ---- Pool / solo ------------------------------------------------------------
// Solo (pays the whole block reward if you ever find one):
//     solo.ckpool.org : 3333      or      public-pool.io : 21496
// Note: pool.nerdminers.org only accepts known NerdMiner clients ("Only allowed
// user agents may subscribe"), so it rejects this firmware.
// Pool list. With one entry the miner just keeps retrying it (with backoff);
// add more host/port pairs here if you ever want automatic failover.
static const char* const POOL_HOSTS[] = {
    "solo.ckpool.org",
};
static const uint16_t POOL_PORTS[] = { 3333 };
#define POOL_COUNT  (sizeof(POOL_HOSTS) / sizeof(POOL_HOSTS[0]))
#define POOL_PASS        "x"

// Ask the pool for an easy share difficulty so that accepted shares arrive
// often enough to measure the *real* hashrate. 0 = do not ask.
// (Pools are free to ignore it; we always obey mining.set_difficulty.)
#define SUGGEST_DIFFICULTY  0.0005

// ---- Mining engines -----------------------------------------------------------
// ESP32 hardware SHA engine on core 1 (verified by a boot self-test; if the
// test fails the firmware falls back to software automatically).
#define USE_HW_SHA          1
// Optimized software hasher on core 0 (shares the core with WiFi). With HW
// disabled/failed, core 1 runs the software hasher as well.
#define USE_SW_WORKER       1

// Run a short raw benchmark (no network) at boot and print the result.
#define BENCHMARK_ON_BOOT   1
#define BENCHMARK_MS        2000

// Seconds between status lines on the serial console.
#define STATS_INTERVAL_S    10

// Onboard LED of DevKit V1 (blinks on every accepted share).
#define LED_PIN             2

// =============================================================================
//  main.cpp  -  ESP32 DevKit V1 SHA-256d miner
//
//  core 1 : hardware-SHA worker   (falls back to software if the self-test fails)
//  core 0 : WiFi + Stratum task + software worker (midstate / early-reject)
//
//  Every candidate is re-checked with an independent, slow SHA-256d before a
//  share is sent, so a glitch in the hardware path can never produce a bogus
//  submission, and the numbers printed here are hashes that were really
//  computed (no padding of the counter).
// =============================================================================
#include <Arduino.h>
#include <WiFi.h>
#include "config.h"
#include "miner_core.h"
#include "stratum.h"
#include "hwsha.h"

static bool g_hw_ok = false;

// ---------------------------------------------------------------------------
//  Worker
// ---------------------------------------------------------------------------
struct WorkerArgs { int id; bool hw; };

static void report_candidates(const Job& job, const uint32_t* cands, uint32_t nc) {
    for (uint32_t i = 0; i < nc; i++) {
        uint8_t digest[32];
        if (!job_check(job, cands[i], digest)) continue;   // exact 256-bit test
        Share s;
        strlcpy(s.job_id, job.id, sizeof(s.job_id));
        strlcpy(s.en2, job.en2, sizeof(s.en2));
        strlcpy(s.ntime, job.ntime, sizeof(s.ntime));
        s.nonce = cands[i];
        s.diff = G.pool_diff;
        double d = digest_to_diff(digest);
        if (d > G.best_diff) G.best_diff = d;
        stratum_push_share(s);
    }
}

static void worker_task(void* arg) {
    const WorkerArgs wa = *(const WorkerArgs*)arg;
    static const uint32_t HW_BATCH = 8192, SW_BATCH = 1024;
    const uint32_t batch = wa.hw ? HW_BATCH : SW_BATCH;

    Job job;
    hw::HwJob hj;
    uint32_t gen = 0, dgen = 0, nonce = 0, en2ctr = 0, iter = 0;
    bool have = false;
    uint32_t cands[16];

    for (;;) {
        // ---- new job from the pool? ----------------------------------------------
        if (!have || G.job_gen != gen) {
            en2ctr = 0; nonce = 0;
            have = build_job(job, wa.id, en2ctr, &gen, &dgen);
            if (!have) { vTaskDelay(pdMS_TO_TICKS(50)); continue; }
            if (wa.hw) hw::prepare(hj, job, hw::eng.swap);
        } else if (G.diff_gen != dgen) {
            refresh_target(job, &dgen);             // only the share target changed
        }

        // ---- search one batch --------------------------------------------------------
        uint32_t done = batch, nc = 0;
        const uint32_t tgt = job.target[7];
        if (wa.hw) {
            nc = hw::run(hj, nonce, batch, tgt, cands, 16, &done);
            G.hashes_hw += done;
        } else {
            for (uint32_t i = 0; i < batch; i++) {
                if (sw_top(job, nonce + i) <= tgt) {
                    cands[nc++] = nonce + i;
                    if (nc == 16) { done = i + 1; break; }
                }
            }
            G.hashes_sw += done;
        }
        if (nc) report_candidates(job, cands, nc);

        // ---- advance: next nonce range, or next extranonce2 after 2^32 -------------
        uint32_t next = nonce + done;
        if (next < nonce) {                          // nonce space exhausted
            en2ctr++;
            have = build_job(job, wa.id, en2ctr, &gen, &dgen);
            if (have && wa.hw) hw::prepare(hj, job, hw::eng.swap);
            nonce = 0;
        } else {
            nonce = next;
        }

        // Let the idle task / watchdog run: 1 ms every ~8 batches (<0.5 % cost).
        if ((++iter & 7) == 0) vTaskDelay(1);
    }
}

// ---------------------------------------------------------------------------
//  Boot-time benchmark (raw engine speed, no network)
// ---------------------------------------------------------------------------
static void benchmark() {
    static Job j;
    static hw::HwJob hj;
    hex2bin(hw::GENESIS_HDR_HEX, j.header, 80);
    job_prepare(j);

    uint32_t cands[4], done, nonce = 0;
    if (g_hw_ok) {
        hw::prepare(hj, j, hw::eng.swap);
        auto measure = [&]() -> double {
            uint64_t total = 0;
            uint32_t t0 = millis();
            while (millis() - t0 < BENCHMARK_MS) {
                hw::run(hj, nonce, 4096, 0, cands, 4, &done);
                nonce += done; total += done;
            }
            return total / (double)(millis() - t0);
        };
        hw::eng.use_ov = false;
        double plain = measure();
        Serial.printf("[bench] hardware SHA : %.1f kH/s (1 core, plain loop)\n", plain);
        uint32_t t0;
        if (hw::eng.ov_ok) {
            hw::eng.use_ov = true;
            double ov = measure();
            Serial.printf("[bench] hardware SHA : %.1f kH/s (1 core, pipelined loop)\n", ov);
            hw::eng.use_ov = ov > plain;
            Serial.printf("[bench] using %s loop\n", hw::eng.use_ov ? "pipelined" : "plain");
        }

        // where does the time go? (see hwsha.h)
        const uint32_t N = 200000;
        t0 = millis(); hw::engine_only(hw::eng.T, N);
        uint32_t te = millis() - t0;
        t0 = millis(); volatile uint32_t ws = hw::writes_only(hw::eng.T, N); (void)ws;
        uint32_t tw = millis() - t0;
        Serial.printf("[bench] engine only : %.1f kH/s-equivalent (no register writes)\n", N / (double)te);
        Serial.printf("[bench] writes only : %.1f kH/s-equivalent (no engine work)\n", N / (double)tw);
    }
    uint64_t total = 0;
    volatile uint32_t sink = 0;                  // keeps the compiler from dropping the work
    uint32_t t0 = millis();
    while (millis() - t0 < BENCHMARK_MS) {
        for (uint32_t i = 0; i < 512; i++) sink = sw_top(j, nonce + i);
        nonce += 512; total += 512;
    }
    Serial.printf("[bench] software SHA : %.1f kH/s (1 core, no WiFi load)\n",
                  total / (double)(millis() - t0));
}

// ---------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(300);
    setCpuFrequencyMhz(240);
    pinMode(LED_PIN, OUTPUT);
    Serial.printf("\n=== ESP32 fast SHA-256d miner | %d MHz | %s ===\n", getCpuFrequencyMhz(), ESP.getChipModel());

    if (!strncmp(POOL_USER, "YOUR_", 5)) {
        Serial.println("Set POOL_USER (your BTC address) and WiFi credentials in src/config.h first!");
        for (;;) delay(1000);
    }

    stratum_init();

#if USE_HW_SHA
    g_hw_ok = hw::init();
#endif
#if BENCHMARK_ON_BOOT
    benchmark();
#endif

    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);                // modem sleep adds latency and steals CPU
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("WiFi");
    for (int i = 0; i < 60 && WiFi.status() != WL_CONNECTED; i++) { delay(500); Serial.print('.'); }
    Serial.printf("\nWiFi %s, IP %s\n", WiFi.status() == WL_CONNECTED ? "up" : "NOT connected yet",
                  WiFi.localIP().toString().c_str());

    static WorkerArgs a_hw = {0, true}, a_sw0 = {1, false}, a_sw1 = {2, false};
    xTaskCreatePinnedToCore(stratum_task, "stratum", 8192, nullptr, 2, nullptr, 0);
    if (g_hw_ok) {
        xTaskCreatePinnedToCore(worker_task, "hw", 8192, &a_hw, 1, nullptr, 1);
#if USE_SW_WORKER
        xTaskCreatePinnedToCore(worker_task, "sw0", 8192, &a_sw0, 1, nullptr, 0);
#endif
    } else {
        xTaskCreatePinnedToCore(worker_task, "sw1", 8192, &a_sw1, 1, nullptr, 1);
        xTaskCreatePinnedToCore(worker_task, "sw0", 8192, &a_sw0, 1, nullptr, 0);
    }
}

// ---------------------------------------------------------------------------
//  Status line every STATS_INTERVAL_S seconds
// ---------------------------------------------------------------------------
void loop() {
    static uint64_t last_hw = 0, last_sw = 0;
    static uint32_t last_ms = millis();
    vTaskDelay(pdMS_TO_TICKS(STATS_INTERVAL_S * 1000));

    uint32_t now = millis();
    uint64_t hw_n = G.hashes_hw, sw_n = G.hashes_sw;
    double dt = (now - last_ms) / 1000.0;
    double hw_k = (hw_n - last_hw) / dt / 1000.0, sw_k = (sw_n - last_sw) / dt / 1000.0;
    last_hw = hw_n; last_sw = sw_n; last_ms = now;

    // "Real" hashrate: what the accepted shares prove (needs a few shares to be meaningful).
    double eff = 0;
    if (G.t_authorized_ms && G.acc_diff_sum > 0)
        eff = G.acc_diff_sum * 4294967296.0 / ((now - G.t_authorized_ms) / 1000.0) / 1000.0;

    Serial.printf("[stat] raw %.1f kH/s (hw %.1f + sw %.1f) | accepted %u rejected %u | "
                  "proven by shares: %.1f kH/s | best diff %.4g | pool diff %g | heap %u\n",
                  hw_k + sw_k, hw_k, sw_k, (unsigned)G.accepted, (unsigned)G.rejected, eff,
                  G.best_diff, G.pool_diff, (unsigned)ESP.getFreeHeap());
}

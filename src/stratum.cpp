// =============================================================================
//  stratum.cpp  -  Stratum v1 client (solo and pool) + job builder
// =============================================================================
#include "stratum.h"
#include <WiFi.h>
#include <ArduinoJson.h>
#include "config.h"
#include <errno.h>

SharedState G;

static WiFiClient cli;
static QueueHandle_t shareQ;
static char   rx[8192];
static size_t rxlen = 0;
static uint32_t msg_id = 10;               // ids 1..9 are reserved for the handshake
static uint32_t last_rx_ms = 0;

struct Pending { uint32_t id; double diff; };
static Pending pend[32];

// ---------------------------------------------------------------------------
void stratum_init() {
    G.mtx = xSemaphoreCreateMutex();
    shareQ = xQueueCreate(16, sizeof(Share));
    G.pool_diff = 1.0;
}

bool stratum_push_share(const Share& s) { return xQueueSend(shareQ, &s, 0) == pdTRUE; }


// ---- connection / failover state ---------------------------------------------
static int      pool_idx   = 0;        // index into POOL_HOSTS / POOL_PORTS
static int      fails      = 0;        // consecutive bad sessions on this pool
static uint32_t backoff_ms = 3000;     // wait before the next attempt (doubles, max 30 s)
static bool     in_session = false;    // TCP connected and handshake started
static bool     authorized = false;    // pool accepted our login in this session
static uint32_t sess_start = 0;
static uint32_t rx_total   = 0;        // bytes received in this session
static int      dbg_lines  = 0;        // first few raw lines are echoed for diagnosis

static void session_failed() {
    fails++;
    backoff_ms = backoff_ms * 2 > 30000 ? 30000 : backoff_ms * 2;
    if (fails >= 3) {
        pool_idx = (pool_idx + 1) % POOL_COUNT;
        fails = 0; backoff_ms = 3000;
        Serial.printf("[stratum] 3 bad sessions in a row -> switching to %s:%u\n",
                      POOL_HOSTS[pool_idx], (unsigned)POOL_PORTS[pool_idx]);
    }
}

// DNS lookup; if the router's DNS fails, fall back once to 8.8.8.8 / 1.1.1.1.
static bool resolve(const char* host, IPAddress& ip) {
    if (WiFi.hostByName(host, ip) == 1 && (uint32_t)ip != 0) return true;
    static bool patched = false;
    if (!patched) {
        patched = true;
        Serial.println("[dns] router DNS failed, switching to 8.8.8.8 / 1.1.1.1");
        WiFi.config(WiFi.localIP(), WiFi.gatewayIP(), WiFi.subnetMask(),
                    IPAddress(8, 8, 8, 8), IPAddress(1, 1, 1, 1));
        return WiFi.hostByName(host, ip) == 1 && (uint32_t)ip != 0;
    }
    return false;
}

static void send_line(const char* s) {
    cli.print(s);
    cli.print('\n');
}

// ---- helpers ----------------------------------------------------------------
static void reverse4(const uint8_t* in, uint8_t* out) {
    out[0] = in[3]; out[1] = in[2]; out[2] = in[1]; out[3] = in[0];
}

static bool hex_field(const char* hex, uint8_t* out, size_t expect) {
    uint8_t tmp[64];
    int n = hex2bin(hex, tmp, sizeof(tmp));
    if (n != (int)expect) return false;
    memcpy(out, tmp, expect);
    return true;
}

// ---- mining.notify ------------------------------------------------------------
static void on_notify(JsonArray p) {
    if (p.size() < 9) return;
    static Notify n;                         // static: too big for the task stack
    memset(&n, 0, sizeof(n));

    strlcpy(n.job_id, p[0] | "", sizeof(n.job_id));

    // prevhash: 8 words, each byte-swapped relative to the header order
    uint8_t ph[32];
    if (!hex_field(p[1] | "", ph, 32)) return;
    for (int i = 0; i < 8; i++) reverse4(ph + 4 * i, n.prevhash + 4 * i);

    int l1 = hex2bin(p[2] | "", n.cb1, CB_MAX);
    int l2 = hex2bin(p[3] | "", n.cb2, CB_MAX);
    if (l1 < 0 || l2 < 0) { Serial.println("[stratum] coinbase too large, job dropped"); return; }
    n.cb1_len = l1; n.cb2_len = l2;

    JsonArray br = p[4];
    if (br.size() > BRANCH_MAX) { Serial.println("[stratum] too many merkle branches"); return; }
    for (JsonVariant b : br) {
        if (!hex_field(b | "", n.branch[n.branch_cnt], 32)) return;
        n.branch_cnt++;
    }

    uint8_t t[4];
    if (!hex_field(p[5] | "", t, 4)) return;  reverse4(t, n.version);
    if (!hex_field(p[6] | "", t, 4)) return;  reverse4(t, n.nbits);
    if (!hex_field(p[7] | "", t, 4)) return;  reverse4(t, n.ntime);
    strlcpy(n.ntime_hex, p[7] | "", sizeof(n.ntime_hex));
    n.clean = p[8] | false;

    xSemaphoreTake(G.mtx, portMAX_DELAY);
    memcpy(&G.notify, &n, sizeof(n));
    G.have_job = true;
    G.job_gen++;
    xSemaphoreGive(G.mtx);
}

// ---- incoming message dispatch ------------------------------------------------
static void handle_line(const char* line) {
    if (dbg_lines < 4) { dbg_lines++; Serial.printf("[rx] %.110s\n", line); }
    JsonDocument doc;
    if (deserializeJson(doc, line)) return;

    const char* method = doc["method"] | "";
    if (method[0]) {
        JsonArray params = doc["params"];
        if (!strcmp(method, "mining.notify")) {
            on_notify(params);
        } else if (!strcmp(method, "mining.set_difficulty")) {
            double d = params[0].as<double>();
            if (d > 0) {
                xSemaphoreTake(G.mtx, portMAX_DELAY);
                G.pool_diff = d;
                G.diff_gen++;
                xSemaphoreGive(G.mtx);
                Serial.printf("[stratum] pool difficulty = %g\n", d);
            }
        } else if (!strcmp(method, "mining.set_extranonce")) {
            const char* e1 = params[0] | "";
            int n = hex2bin(e1, G.en1, sizeof(G.en1));
            if (n >= 0) { G.en1_len = n; G.en2_size = params[1] | 4; }
        } else if (!strcmp(method, "client.reconnect")) {
            cli.stop();
        }
        return;
    }

    uint32_t id = doc["id"] | 0;
    JsonVariant result = doc["result"];
    if (id == 1) {                                   // subscribe
        if (result.isNull()) { Serial.println("[stratum] subscribe refused by pool"); cli.stop(); return; }
        const char* e1 = result[1] | "";
        int n = hex2bin(e1, G.en1, sizeof(G.en1));
        if (n < 0) { Serial.println("[stratum] bad extranonce1"); cli.stop(); return; }
        G.en1_len = n;
        G.en2_size = result[2] | 4;
        if (G.en2_size < 2 || G.en2_size > 8) { Serial.println("[stratum] unsupported extranonce2 size"); cli.stop(); return; }

        char buf[256];
        if ((double)SUGGEST_DIFFICULTY > 0) {
            snprintf(buf, sizeof(buf), "{\"id\":3,\"method\":\"mining.suggest_difficulty\",\"params\":[%g]}", (double)SUGGEST_DIFFICULTY);
            send_line(buf);
        }
        snprintf(buf, sizeof(buf), "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}", POOL_USER, POOL_PASS);
        send_line(buf);
    } else if (id == 2) {                            // authorize
        if (result | false) {
            G.t_authorized_ms = millis();
            authorized = true;
            Serial.println("[stratum] authorized");
        } else {
            Serial.println("[stratum] AUTHORIZATION FAILED - check POOL_USER");
        }
    } else if (id >= 10) {                           // share result
        double d = 1.0;
        for (auto& p : pend) if (p.id == id) { d = p.diff; p.id = 0; break; }
        if (result | false) {
            G.accepted++;
            G.acc_diff_sum += d;
            digitalWrite(LED_PIN, HIGH);
            Serial.printf("[share] ACCEPTED  (diff %g)\n", d);
        } else {
            G.rejected++;
            const char* why = doc["error"][1] | "unknown";
            Serial.printf("[share] rejected: %s\n", why);
        }
    }
}

static void send_pending_shares() {
    Share s;
    while (xQueueReceive(shareQ, &s, 0) == pdTRUE) {
        uint32_t id = msg_id++;
        for (auto& p : pend) if (p.id == 0) { p.id = id; p.diff = s.diff; break; }
        char buf[320];
        snprintf(buf, sizeof(buf),
                 "{\"id\":%u,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%08x\"]}",
                 (unsigned)id, POOL_USER, s.job_id, s.en2, s.ntime, (unsigned)s.nonce);
        send_line(buf);
        G.submitted++;
    }
}

// ---- connection task ----------------------------------------------------------
void stratum_task(void*) {
    uint32_t led_off_at = 0;
    for (;;) {
        if (WiFi.status() != WL_CONNECTED) { vTaskDelay(pdMS_TO_TICKS(500)); continue; }

        // ---- session ended? (closed by the pool, error, timeout ...) ----------------
        if (in_session && !cli.connected()) {
            in_session = false;
            uint32_t life = millis() - sess_start;
            Serial.printf("[stratum] disconnected after %u ms (rx %u bytes, authorized=%d)\n",
                          (unsigned)life, (unsigned)rx_total, (int)authorized);
            cli.stop();
            G.have_job = false;
            if (authorized && life > 30000) { fails = 0; backoff_ms = 3000; }
            else session_failed();
            Serial.printf("[stratum] retry in %u ms\n", (unsigned)backoff_ms);
            vTaskDelay(pdMS_TO_TICKS(backoff_ms));
            continue;
        }

        // ---- open a new session --------------------------------------------------------
        if (!in_session) {
            G.have_job = false;
            const char* host = POOL_HOSTS[pool_idx];
            uint16_t    port = POOL_PORTS[pool_idx];
            IPAddress ip;
            if (!resolve(host, ip)) {
                Serial.printf("[stratum] DNS failed for %s, retry in %u ms\n", host, (unsigned)backoff_ms);
                session_failed();
                vTaskDelay(pdMS_TO_TICKS(backoff_ms));
                continue;
            }
            Serial.printf("[stratum] connecting to %s (%s):%u ...\n", host, ip.toString().c_str(), (unsigned)port);
            uint32_t t0 = millis();
            errno = 0;
            if (!cli.connect(ip, port, 10000)) {
                Serial.printf("[stratum] TCP connect FAILED after %u ms (errno %d), retry in %u ms\n",
                              (unsigned)(millis() - t0), errno, (unsigned)backoff_ms);
                cli.stop();
                session_failed();
                vTaskDelay(pdMS_TO_TICKS(backoff_ms));
                continue;
            }
            Serial.printf("[stratum] TCP connected in %u ms\n", (unsigned)(millis() - t0));
            cli.setNoDelay(true);
            in_session = true; authorized = false; dbg_lines = 0; rx_total = 0;
            rxlen = 0; last_rx_ms = sess_start = millis();
            memset(pend, 0, sizeof(pend));
            xQueueReset(shareQ);
            send_line("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"esp32-fastminer/1.0\"]}");
        }

        // read whatever has arrived
        int avail = cli.available();
        if (avail > 0) {
            if (rxlen + avail >= sizeof(rx)) avail = sizeof(rx) - 1 - rxlen;
            if (avail <= 0) { Serial.println("[stratum] rx overflow, reconnecting"); cli.stop(); rxlen = 0; continue; }
            int n = cli.read((uint8_t*)rx + rxlen, avail);
            if (n > 0) { rxlen += n; rx_total += n; last_rx_ms = millis(); }
            rx[rxlen] = 0;
            char* start = rx;
            char* nl;
            while ((nl = (char*)memchr(start, '\n', rx + rxlen - start))) {
                *nl = 0;
                if (nl > start) handle_line(start);
                start = nl + 1;
            }
            size_t rest = rx + rxlen - start;
            memmove(rx, start, rest);
            rxlen = rest;
        } else if (millis() - last_rx_ms > 300000) {
            Serial.println("[stratum] no data for 5 min, reconnecting");
            cli.stop();
        }

        send_pending_shares();

        if (digitalRead(LED_PIN) && millis() - led_off_at > 60) { digitalWrite(LED_PIN, LOW); led_off_at = millis(); }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
}

// ---- job construction -----------------------------------------------------------
// Called from several worker tasks, so everything lives on the caller's stack.
bool build_job(Job& j, int worker, uint32_t en2ctr, uint32_t* gen_out, uint32_t* dgen_out) {
    Notify n;
    uint8_t en1[8], en1_len, en2_size;
    double diff;

    xSemaphoreTake(G.mtx, portMAX_DELAY);
    bool ok = G.have_job;
    if (ok) {
        memcpy(&n, &G.notify, sizeof(n));
        memcpy(en1, G.en1, sizeof(en1));
        en1_len = G.en1_len; en2_size = G.en2_size;
        diff = G.pool_diff;
        *gen_out = G.job_gen;
        *dgen_out = G.diff_gen;
    }
    xSemaphoreGive(G.mtx);
    if (!ok) return false;

    // extranonce2: unique per worker and per counter value, big-endian in en2_size bytes
    uint8_t en2[8] = {0};
    uint64_t v = ((uint64_t)en2ctr * NUM_WORKER_SLOTS) + (uint32_t)(worker % NUM_WORKER_SLOTS);
    for (int i = 0; i < en2_size; i++) en2[en2_size - 1 - i] = (uint8_t)(v >> (8 * i));

    // coinbase = coinb1 | extranonce1 | extranonce2 | coinb2
    uint8_t cb[2 * CB_MAX + 16];
    size_t l = 0;
    memcpy(cb + l, n.cb1, n.cb1_len); l += n.cb1_len;
    memcpy(cb + l, en1, en1_len);     l += en1_len;
    memcpy(cb + l, en2, en2_size);    l += en2_size;
    memcpy(cb + l, n.cb2, n.cb2_len); l += n.cb2_len;

    uint8_t root[32];
    sha256d(cb, l, root);
    for (int i = 0; i < n.branch_cnt; i++) {
        uint8_t t[64];
        memcpy(t, root, 32);
        memcpy(t + 32, n.branch[i], 32);
        sha256d(t, 64, root);
    }

    // header: version | prevhash | merkle root | ntime | nbits | nonce(0)
    memcpy(j.header + 0,  n.version, 4);
    memcpy(j.header + 4,  n.prevhash, 32);
    memcpy(j.header + 36, root, 32);
    memcpy(j.header + 68, n.ntime, 4);
    memcpy(j.header + 72, n.nbits, 4);
    memset(j.header + 76, 0, 4);

    strlcpy(j.id, n.job_id, sizeof(j.id));
    strlcpy(j.ntime, n.ntime_hex, sizeof(j.ntime));
    bin2hex(en2, en2_size, j.en2);

    job_prepare(j);
    diff_to_target(diff, j.target);
    return true;
}

void refresh_target(Job& j, uint32_t* dgen_out) {
    xSemaphoreTake(G.mtx, portMAX_DELAY);
    double d = G.pool_diff;
    *dgen_out = G.diff_gen;
    xSemaphoreGive(G.mtx);
    diff_to_target(d, j.target);
}

// Difficulty = (0xFFFF * 2^208) / hash, digest bytes are a little-endian number.
double digest_to_diff(const uint8_t digest[32]) {
    double v = 0;
    for (int k = 7; k >= 0; k--) v = v * 4294967296.0 + (double)load_le32(digest + 4 * k);
    if (v <= 0) return 1e300;
    return 65535.0 * ldexp(1.0, 208) / v;
}

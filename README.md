# PipeMiner32

A Bitcoin (SHA-256d) solo/pool miner for the **classic ESP32** (ESP32-D0WD / WROOM-32, DevKit V1) that
drives the hardware SHA engine directly and **overlaps register writes with engine work**.
PlatformIO + Arduino, Stratum v1.

It is a learning / lottery project, not a way to make money: at ~0.5 MH/s the chance of finding a block
is practically zero.

## Results (ESP32-D0WD-V3 DevKit, 240 MHz, one hardware core + one software core)

| Loop | Hardware core |
|---|---|
| plain (write block, start, wait, ...) | 394.5 kH/s |
| pipelined (writes hidden behind the engine) | **534.0 kH/s** |
| whole miner, `raw` incl. software core | ~560 kH/s |

A runtime-tunable delay loop (shorter delays, found by the tuner) was tried as well and was about 1.5 %
*slower* (525.8 kH/s): the delays are not the bottleneck, the loop overhead is. Compile-time `nop` delays
are used.

Boot diagnostics show where the time goes: the engine alone is ~803 kH/s-equivalent and the TEXT register
writes alone ~862, so the plain loop ends up at roughly 1 / (1/803 + 1/862). Pipelining attacks exactly that.

`raw` is the number of hashes actually computed. It is not confirmed by a pool: at pool difficulty 10000
(solo.ckpool.org) accepted shares essentially never arrive at this speed.

## How it works
The classic ESP32 SHA engine cannot resume from a midstate, so every nonce costs 3 block operations (+2 LOADs).
`hwsha.h` talks to the registers directly and, while the engine is busy with one block, already writes the
words of the next one (in ascending order, after a short delay, so a word is never overwritten before the
engine has read it). Espressif does not document this timing, so:

* at boot the delays after the engine is kicked (B/C) are **tuned** from a list of presets: the longest
  ones are tried first, the search stops at the first failure against the software hash, and the preset
  two steps safer is used (on the development board that gave B=C=14 `nop`s);
* the self-test runs the real IRAM code at real speed; if it fails, the miner falls back to the plain loop,
  and if the engine itself fails the self-test, to software only;
* delays can only make writes later, never earlier, which is the safe direction;
* every candidate is re-hashed with an independent slow SHA-256d before it is submitted.

A wrong hash in pipelined mode would show up as a silently *missed* result, not as a rejected share, so
the boot test and the safety margin are the only guards. Treat the mode as experimental.

## Quick start
1. Copy `src/secrets.example.h` to `src/secrets.h` and fill in WiFi (2.4 GHz) and your payout address
   (`POOL_USER`, optionally `.workername`). `secrets.h` is git-ignored.
2. Pick a pool in `src/config.h` (default `solo.ckpool.org:3333`).
3. `pio run -t upload && pio device monitor`

At boot you get the SHA engine self-test, the delay tuning and a benchmark, then a status line every 10 s:

```
[stat] raw 561.1 kH/s (hw 528.6 + sw 32.5) | accepted 0 rejected 0 | ... | pool diff 10000
```

Pool notes: `pool.nerdminers.org` only accepts known NerdMiner clients and rejects this firmware.
`solo.ckpool.org:3333` and `public-pool.io:21496` accept it (check each pool's current rules).

## Architecture
| Where | What |
|---|---|
| core 1 | hardware SHA-256 worker (`hwsha.h`) |
| core 0 | WiFi, Stratum task, software worker (`miner_core.h`: midstate, precomputed rounds, early reject) |

Extranonce2 is unique per worker, so workers never repeat each other's work. Reconnects use exponential
backoff and the pool list fails over after repeated bad sessions.

## Tests (host, no hardware)
`test/host_test.cpp`: SHA core vs. reference, genesis block, random headers.
`test/hw_protocol_test.cpp`: software model of the ESP32 SHA engine driven with the words and order used by
the plain loop. The pipelined loop and its timing can only be verified on a real board.

## Status
Tested on one ESP32-D0WD-V3 DevKit. Other ESP32 revisions or boards may need different delays (the tuner
handles that) or may fail the self-test (then the plain loop is used).

## License
MIT

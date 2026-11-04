// Minimal host stub so hwsha.h can be compiled/inspected off-target.
#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#define IRAM_ATTR
#define DRAM_ATTR
struct SerialStub {
    template <typename... A> void printf(const char* f, A... a) { ::printf(f, a...); }
    void println(const char* s) { puts(s); }
    void flush() {}
};
static SerialStub Serial;

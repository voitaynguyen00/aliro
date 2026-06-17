#include "aliro/core/log.h"
#include <cstdarg>
#include <cstdio>

namespace aliro::log {

// Plain globals — intentionally not thread-safe so this header compiles on
// embedded targets that lack atomic/mutex support. Call setCallback() before
// spawning any threads that might log.
static Callback gCallback = nullptr;
static Level    gMinLevel = Level::DEBUG;

void setCallback(Callback cb, Level minLevel) {
    gCallback = cb;
    gMinLevel = minLevel;
}

void dispatch(Level level, const char* file, int line, const char* fmt, ...) {
    if (static_cast<uint8_t>(level) < static_cast<uint8_t>(gMinLevel)) return;
    if (!gCallback) return;

    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    gCallback(level, file, line, buf);
}

} // namespace aliro::log

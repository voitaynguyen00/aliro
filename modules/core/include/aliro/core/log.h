#pragma once

#include <cstdint>

namespace aliro::log {

enum class Level : uint8_t {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    NONE = 4,  ///< Suppress all output when passed to setCallback().
};

/// Callback signature: level, source file, line number, formatted message.
using Callback = void (*)(Level level, const char* file, int line, const char* message);

/// Register a log sink. Pass nullptr to disable logging.
/// minLevel filters out messages below the given severity.
/// Not thread-safe; call before any concurrent usage.
void setCallback(Callback cb, Level minLevel = Level::DEBUG);

/// Internal dispatcher — use the ALIRO_LOG_* macros instead.
void dispatch(Level level, const char* file, int line, const char* fmt, ...);

}  // namespace aliro::log

// ---------------------------------------------------------------------------
// Macros — set ALIRO_LOG_DISABLE to strip all logging at compile time.
// ---------------------------------------------------------------------------
#ifdef ALIRO_LOG_DISABLE
#define ALIRO_LOG_DEBUG(fmt, ...) ((void)0)
#define ALIRO_LOG_INFO(fmt, ...) ((void)0)
#define ALIRO_LOG_WARN(fmt, ...) ((void)0)
#define ALIRO_LOG_ERROR(fmt, ...) ((void)0)
#else
#define ALIRO_LOG_DEBUG(fmt, ...)                                          \
    ::aliro::log::dispatch(::aliro::log::Level::DEBUG, __FILE__, __LINE__, \
                           fmt __VA_OPT__(, ) __VA_ARGS__)
#define ALIRO_LOG_INFO(fmt, ...)                                          \
    ::aliro::log::dispatch(::aliro::log::Level::INFO, __FILE__, __LINE__, \
                           fmt __VA_OPT__(, ) __VA_ARGS__)
#define ALIRO_LOG_WARN(fmt, ...)                                          \
    ::aliro::log::dispatch(::aliro::log::Level::WARN, __FILE__, __LINE__, \
                           fmt __VA_OPT__(, ) __VA_ARGS__)
#define ALIRO_LOG_ERROR(fmt, ...)                                          \
    ::aliro::log::dispatch(::aliro::log::Level::ERROR, __FILE__, __LINE__, \
                           fmt __VA_OPT__(, ) __VA_ARGS__)
#endif

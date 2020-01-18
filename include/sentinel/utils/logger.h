#ifndef SENTINEL_UTILS_LOGGER_H
#define SENTINEL_UTILS_LOGGER_H

#include "sentinel/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sentinel_log_level {
    SENTINEL_LOG_TRACE = 0,
    SENTINEL_LOG_DEBUG = 1,
    SENTINEL_LOG_INFO  = 2,
    SENTINEL_LOG_WARN  = 3,
    SENTINEL_LOG_ERROR = 4,
    SENTINEL_LOG_FATAL = 5,
    SENTINEL_LOG_OFF   = 6
} sentinel_log_level_t;

typedef void (*sentinel_log_callback_t)(sentinel_log_level_t level,
    const char* file, int line, const char* fmt, ...);

void sentinel_log_init(sentinel_log_level_t min_level);
void sentinel_log_set_level(sentinel_log_level_t level);
void sentinel_log_set_callback(sentinel_log_callback_t cb);
void sentinel_log_set_file(const char* filepath);
void sentinel_log_write(sentinel_log_level_t level, const char* file,
                        int line, const char* fmt, ...);
void sentinel_log_shutdown(void);

#define SLOG_TRACE(...) sentinel_log_write(SENTINEL_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define SLOG_DEBUG(...) sentinel_log_write(SENTINEL_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define SLOG_INFO(...)  sentinel_log_write(SENTINEL_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define SLOG_WARN(...)  sentinel_log_write(SENTINEL_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define SLOG_ERROR(...) sentinel_log_write(SENTINEL_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define SLOG_FATAL(...) sentinel_log_write(SENTINEL_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif

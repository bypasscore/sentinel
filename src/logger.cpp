#include "sentinel/utils/logger.h"
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

static sentinel_log_level_t g_min_level = SENTINEL_LOG_INFO;
static sentinel_log_callback_t g_callback = nullptr;
static FILE* g_logfile = nullptr;
static bool g_owns_file = false;

static const char* level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

static const char* level_colors[] = {
    "\033[90m", "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[35m"
};

void sentinel_log_init(sentinel_log_level_t min_level) {
    g_min_level = min_level;
    g_callback = nullptr;
    g_logfile = nullptr;
    g_owns_file = false;
}

void sentinel_log_set_level(sentinel_log_level_t level) {
    g_min_level = level;
}

void sentinel_log_set_callback(sentinel_log_callback_t cb) {
    g_callback = cb;
}

void sentinel_log_set_file(const char* filepath) {
    if (g_logfile && g_owns_file) {
        fclose(g_logfile);
    }
    g_logfile = fopen(filepath, "a");
    g_owns_file = (g_logfile != nullptr);
}

void sentinel_log_write(sentinel_log_level_t level, const char* file,
                        int line, const char* fmt, ...) {
    if (level < g_min_level) return;

    /* Get timestamp */
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    /* Extract filename from path */
    const char* fname = file;
    const char* p = strrchr(file, '/');
    if (p) fname = p + 1;
    const char* q = strrchr(fname, '\');
    if (q) fname = q + 1;

    /* Format the user message */
    char msgbuf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    va_end(args);

    /* Write to stderr with color */
    int lvl = (int)level;
    if (lvl < 0) lvl = 0;
    if (lvl > 5) lvl = 5;

    fprintf(stderr, "%s%s [%s] %s:%d: %s\033[0m\n",
            level_colors[lvl], timebuf, level_strings[lvl],
            fname, line, msgbuf);

    /* Write to file if configured */
    if (g_logfile) {
        fprintf(g_logfile, "%s [%s] %s:%d: %s\n",
                timebuf, level_strings[lvl], fname, line, msgbuf);
        fflush(g_logfile);
    }

    /* Invoke callback if registered */
    if (g_callback) {
        va_start(args, fmt);
        g_callback(level, file, line, fmt);
        va_end(args);
    }

#ifdef _WIN32
    /* Also output to debugger */
    char dbgbuf[2200];
    snprintf(dbgbuf, sizeof(dbgbuf), "[sentinel] %s %s:%d: %s\n",
             level_strings[lvl], fname, line, msgbuf);
    OutputDebugStringA(dbgbuf);
#endif
}

void sentinel_log_shutdown(void) {
    if (g_logfile && g_owns_file) {
        fclose(g_logfile);
        g_logfile = nullptr;
    }
    g_callback = nullptr;
}

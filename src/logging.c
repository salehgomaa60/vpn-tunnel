#include "logging.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

static log_level_t current_log_level = LOG_LEVEL_INFO;

void log_set_level(log_level_t level) {
    current_log_level = level;
}

log_level_t log_get_level(void) {
    return current_log_level;
}

static const char *level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO ";
        case LOG_LEVEL_WARN:  return "WARN ";
        case LOG_LEVEL_ERROR: return "ERROR";
        default:              return "UNKNOWN";
    }
}

void log_message(log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level < current_log_level || level >= LOG_LEVEL_NONE) {
        return;
    }

    /* Extract basename from file path for cleaner logs */
    const char *base = strrchr(file, '/');
    if (!base) {
        base = strrchr(file, '\\');
    }
    const char *filename = base ? (base + 1) : file;

    time_t now = time(NULL);
    struct tm tm_buf;
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(stderr, "[%s] [%s] [%s:%d] ", time_str, level_to_string(level), filename, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

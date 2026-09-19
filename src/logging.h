#ifndef VPN_LOGGING_H
#define VPN_LOGGING_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_NONE  = 4
} log_level_t;

void log_set_level(log_level_t level);
log_level_t log_get_level(void);

/* Format and print a log message safely.
 * SECURITY RULE: NEVER pass private keys, shared secrets, session keys,
 * or decrypted payload plaintexts into logging functions.
 */
void log_message(log_level_t level, const char *file, int line, const char *fmt, ...);

#define LOG_DEBUG(...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#endif /* VPN_LOGGING_H */

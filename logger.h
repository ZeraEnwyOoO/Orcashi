#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

/* ============================================================================
 * LOG LEVELS
 * ============================================================================ */

typedef enum {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4,
    LOG_LEVEL_TRACE = 5
} LogLevel;

/* ============================================================================
 * LOGGER FUNCTIONS
 * ============================================================================ */

/* Initialize logger with log file path */
int logger_init(const char* log_file);

/* Set log level (default: LOG_LEVEL_INFO) */
void logger_set_level(LogLevel level);

/* Get current log level */
LogLevel logger_get_level(void);

/* Close logger (flush and close file) */
void logger_close(void);

/* ============================================================================
 * LOG MACROS
 * ============================================================================ */

#define LOG_ERROR(fmt, ...)   logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    logger_log(LOG_LEVEL_WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    logger_log(LOG_LEVEL_INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)   logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...)   logger_log(LOG_LEVEL_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* ============================================================================
 * CORE LOG FUNCTION
 * ============================================================================ */

/* Log a message with level, file, line */
void logger_log(LogLevel level, const char* file, int line, const char* format, ...);

/* ============================================================================
 * UTILITY
 * ============================================================================ */

/* Convert log level to string */
const char* logger_level_to_string(LogLevel level);

/* Check if log level is enabled */
bool logger_is_enabled(LogLevel level);

#endif /* LOGGER_H */

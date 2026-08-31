#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static FILE* g_log_file = NULL;
static LogLevel g_log_level = LOG_LEVEL_INFO;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;
static char g_log_path[512] = {0};

/* ============================================================================
 * LOG LEVEL STRINGS
 * ============================================================================ */

static const char* level_strings[] = {
    "NONE",
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG",
    "TRACE"
};

const char* logger_level_to_string(LogLevel level) {
    if (level < LOG_LEVEL_NONE || level > LOG_LEVEL_TRACE) {
        return "UNKNOWN";
    }
    return level_strings[level];
}

/* ============================================================================
 * INIT / CLOSE
 * ============================================================================ */

int logger_init(const char* log_file) {
    pthread_mutex_lock(&g_log_mutex);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_log_mutex);
        return 0;
    }
    
    /* Create directory if it doesn't exist */
    if (log_file) {
        strncpy(g_log_path, log_file, sizeof(g_log_path) - 1);
        g_log_path[sizeof(g_log_path) - 1] = '\0';
        
        /* Create directory */
        char dir[512];
        strncpy(dir, log_file, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        
        char* last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir, 0755);
        }
        
        g_log_file = fopen(log_file, "a");
        if (!g_log_file) {
            fprintf(stderr, "[LOGGER] Failed to open log file: %s\n", strerror(errno));
            pthread_mutex_unlock(&g_log_mutex);
            return -1;
        }
        
        setvbuf(g_log_file, NULL, _IOLBF, 0);
    } else {
        /* Log to stderr if no file */
        g_log_file = stderr;
    }
    
    g_initialized = true;
    
    LOG_INFO("Logger initialized (log file: %s)", log_file ? log_file : "stderr");
    
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void logger_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        LOG_INFO("Logger closing...");
        fclose(g_log_file);
    }
    
    g_log_file = NULL;
    g_initialized = false;
    
    pthread_mutex_unlock(&g_log_mutex);
}

/* ============================================================================
 * LOG LEVEL
 * ============================================================================ */

void logger_set_level(LogLevel level) {
    pthread_mutex_lock(&g_log_mutex);
    g_log_level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

LogLevel logger_get_level(void) {
    pthread_mutex_lock(&g_log_mutex);
    LogLevel level = g_log_level;
    pthread_mutex_unlock(&g_log_mutex);
    return level;
}

bool logger_is_enabled(LogLevel level) {
    pthread_mutex_lock(&g_log_mutex);
    bool enabled = (level <= g_log_level && level != LOG_LEVEL_NONE);
    pthread_mutex_unlock(&g_log_mutex);
    return enabled;
}

/* ============================================================================
 * CORE LOG FUNCTION
 * ============================================================================ */

void logger_log(LogLevel level, const char* file, int line, const char* format, ...) {
    if (!logger_is_enabled(level)) {
        return;
    }
    
    pthread_mutex_lock(&g_log_mutex);
    
    /* Get timestamp */
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    
    /* Get thread ID */
    pthread_t tid = pthread_self();
    
    /* Format message */
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    /* Get filename without path */
    const char* filename = file;
    const char* last_slash = strrchr(file, '/');
    if (last_slash) {
        filename = last_slash + 1;
    }
    
    /* Write to log */
    if (g_log_file) {
        fprintf(g_log_file, "[%02d:%02d:%02d] [%s] [%s:%d] [tid:%lu] %s\n",
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                logger_level_to_string(level),
                filename, line,
                (unsigned long)tid,
                message);
        fflush(g_log_file);
    }
    
    /* Also print to stderr for ERROR and WARN */
    if (level <= LOG_LEVEL_WARN) {
        fprintf(stderr, "[%s] %s\n", logger_level_to_string(level), message);
        fflush(stderr);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}

/* ============================================================================
 * DEBUG HELPERS
 * ============================================================================ */

void logger_debug_hex(const char* label, const unsigned char* data, size_t len) {
    if (!logger_is_enabled(LOG_LEVEL_DEBUG)) return;
    
    char hex[4096];
    char* ptr = hex;
    size_t remaining = sizeof(hex);
    
    for (size_t i = 0; i < len && remaining > 4; i++) {
        int written = snprintf(ptr, remaining, "%02x ", data[i]);
        ptr += written;
        remaining -= written;
        
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            *ptr++ = '\n';
            remaining--;
        }
    }
    
    LOG_DEBUG("%s: %s", label, hex);
}

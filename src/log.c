// SPDX-License-Identifier: Apache-2.0
/*
 * log.c - Tiny leveled logger with an optional sink so the GUI can mirror
 * messages into its on-screen console.
 */

#include "byedpi.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static bd_log_level  g_level = BD_LOG_INFO;
static bd_log_sink   g_sink  = NULL;
static void         *g_sink_user = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *level_tag(bd_log_level l)
{
    switch (l) {
    case BD_LOG_ERROR: return "ERROR";
    case BD_LOG_WARN:  return "WARN ";
    case BD_LOG_INFO:  return "INFO ";
    case BD_LOG_DEBUG: return "DEBUG";
    default:           return "?????";
    }
}

void bd_log_set_sink(bd_log_sink sink, void *user)
{
    pthread_mutex_lock(&g_lock);
    g_sink = sink;
    g_sink_user = user;
    pthread_mutex_unlock(&g_lock);
}

void bd_log_set_level(bd_log_level level)
{
    g_level = level;
}

void bd_log(bd_log_level level, const char *fmt, ...)
{
    if (level > g_level)
        return;

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char stamp[16];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(stamp, sizeof(stamp), "%H:%M:%S", &tmv);

    char line[1152];
    snprintf(line, sizeof(line), "[%s] %s  %s", stamp, level_tag(level), msg);

    pthread_mutex_lock(&g_lock);
    FILE *out = (level <= BD_LOG_WARN) ? stderr : stdout;
    fprintf(out, "%s\n", line);
    fflush(out);
    bd_log_sink sink = g_sink;
    void *user = g_sink_user;
    pthread_mutex_unlock(&g_lock);

    if (sink)
        sink(level, line, user);
}

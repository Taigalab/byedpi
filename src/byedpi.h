// SPDX-License-Identifier: Apache-2.0
/*
 * byedpi.h - Shared configuration, logging and engine interface.
 *
 * Passewall - A Linux DPI circumvention tool (a GoodbyeDPI equivalent).
 * Copyright 2026 The Passewall Authors.
 */

#ifndef BYEDPI_H
#define BYEDPI_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define BYEDPI_APP_ID     "io.github.taigalinux.Passewall"
#define BYEDPI_APP_NAME   "Passewall"
#define BYEDPI_VERSION    "0.1.0"
#define BYEDPI_QUEUE_NUM  100

/* Firewall mark stamped on every packet we inject. An ACCEPT rule matching
 * this mark is installed above the NFQUEUE rules so that our own injected
 * packets skip the queue instead of being intercepted again (which would
 * recurse endlessly). */
#define BYEDPI_FWMARK     0xDED

/* Run modes selected on the command line. */
typedef enum {
    BD_MODE_GUI = 0,   /* full graphical interface (default)          */
    BD_MODE_NOGUI,     /* headless, no window                         */
    BD_MODE_TRAY       /* tray icon only, no main window on startup   */
} bd_mode;

/* Log severity levels. */
typedef enum {
    BD_LOG_ERROR = 0,
    BD_LOG_WARN,
    BD_LOG_INFO,
    BD_LOG_DEBUG
} bd_log_level;

/*
 * Runtime configuration. A single instance is owned by main() and shared
 * (by pointer) with the engine and the GUI. Fields marked "live" may be
 * changed by the GUI while the engine runs; the engine reads them per-packet.
 */
typedef struct bd_config {
    char dns_addr[64];       /* primary upstream DNS server IP        */
    char dns_fallback[64];   /* fallback upstream DNS server IP       */
    int  dns_upstream_port;  /* upstream DNS port (usually 53)        */

    int  ttl;                /* fake-packet TTL / hop limit (1-10)    */

    bool enable_http;        /* live: fragment HTTP Host header       */
    bool enable_tls;         /* live: split TLS ClientHello at SNI    */
    bool enable_dns;         /* live: intercept + forward DNS         */
    bool enable_quic;        /* live: manage QUIC/HTTP3 (UDP 443)     */

    bool ipv6;               /* also install ip6tables rules          */
    bool verbose;            /* live: log every intercepted packet    */

    bd_mode mode;            /* run mode                              */

    bool resolved_active;    /* systemd-resolved detected on :53      */
} bd_config;

/* Logging callback signature. The GUI installs one to mirror logs into the
 * on-screen console; headless mode uses the default stderr logger. */
typedef void (*bd_log_sink)(bd_log_level level, const char *line, void *user);

void bd_log_set_sink(bd_log_sink sink, void *user);
void bd_log_set_level(bd_log_level level);
void bd_log(bd_log_level level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define BD_ERR(...)   bd_log(BD_LOG_ERROR, __VA_ARGS__)
#define BD_WARN(...)  bd_log(BD_LOG_WARN,  __VA_ARGS__)
#define BD_INFO(...)  bd_log(BD_LOG_INFO,  __VA_ARGS__)
#define BD_DEBUG(...) bd_log(BD_LOG_DEBUG, __VA_ARGS__)

/*
 * Engine lifecycle. The engine owns the netfilter queue, the raw injection
 * sockets, the iptables rules and the receive thread. start() is idempotent
 * safe: calling it while already running returns 0 without side effects.
 */
typedef struct bd_engine bd_engine;

bd_engine *bd_engine_new(bd_config *cfg);
int        bd_engine_start(bd_engine *e);   /* 0 on success, -1 on error   */
void       bd_engine_stop(bd_engine *e);
bool       bd_engine_is_running(bd_engine *e);
void       bd_engine_free(bd_engine *e);

/* Statistics, read-only snapshot used by the GUI status line. */
typedef struct {
    uint64_t packets_seen;
    uint64_t tcp_split;
    uint64_t fake_sent;
    uint64_t dns_forwarded;
    uint64_t quic_handled;
} bd_stats;

void bd_engine_get_stats(bd_engine *e, bd_stats *out);

#endif /* BYEDPI_H */

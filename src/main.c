// SPDX-License-Identifier: Apache-2.0
/*
 * main.c - Command line parsing, environment preflight checks and mode
 * dispatch (GUI / headless / tray).
 */

#include "byedpi.h"
#include "iptables.h"

#ifdef HAVE_GUI
#include "gui/gui.h"
#endif

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void set_defaults(bd_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->dns_addr, sizeof(cfg->dns_addr), "%s", "1.1.1.1");
    snprintf(cfg->dns_fallback, sizeof(cfg->dns_fallback), "%s", "8.8.8.8");
    cfg->dns_upstream_port = 53;
    cfg->ttl         = 5;
    cfg->enable_http = true;
    cfg->enable_tls  = true;
    cfg->enable_dns  = true;
    cfg->enable_quic = true;
    cfg->ipv6        = true;
    cfg->verbose     = false;
    cfg->mode        = BD_MODE_GUI;
}

static void usage(const char *argv0)
{
    printf(
"%s %s - DPI circumvention for Linux (a GoodbyeDPI equivalent)\n"
"\n"
"Usage: %s [OPTIONS]\n"
"\n"
"Modes:\n"
"  (default)          launch the full GTK4 GUI\n"
"  --no-gui           run headless (no window), CLI behavior\n"
"  --tray             start with only a tray icon, no main window\n"
"\n"
"Options:\n"
"  --dns-addr <ip>    upstream DNS server        (default 1.1.1.1)\n"
"  --ttl <n>          fake packet TTL, 1-10      (default 5)\n"
"  --no-ipv6          do not install ip6tables rules\n"
"  --verbose          log every intercepted packet\n"
"  -h, --help         show this help and exit\n"
"  -V, --version      show version and exit\n"
"\n"
"ByeDPI must run as root (or with CAP_NET_ADMIN + CAP_NET_RAW) because it\n"
"programs iptables and injects raw packets.\n",
        BYEDPI_APP_NAME, BYEDPI_VERSION, argv0);
}

static int parse_args(int argc, char **argv, bd_config *cfg)
{
    enum {
        OPT_DNS = 1000, OPT_TTL, OPT_NO_IPV6, OPT_NO_GUI, OPT_TRAY, OPT_VERBOSE
    };
    static const struct option longopts[] = {
        { "dns-addr", required_argument, 0, OPT_DNS     },
        { "ttl",      required_argument, 0, OPT_TTL     },
        { "no-ipv6",  no_argument,       0, OPT_NO_IPV6 },
        { "no-gui",   no_argument,       0, OPT_NO_GUI  },
        { "tray",     no_argument,       0, OPT_TRAY    },
        { "verbose",  no_argument,       0, OPT_VERBOSE },
        { "help",     no_argument,       0, 'h'         },
        { "version",  no_argument,       0, 'V'         },
        { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "hV", longopts, NULL)) != -1) {
        switch (c) {
        case OPT_DNS:
            snprintf(cfg->dns_addr, sizeof(cfg->dns_addr), "%s", optarg);
            break;
        case OPT_TTL: {
            int t = atoi(optarg);
            if (t < 1 || t > 10) {
                fprintf(stderr, "error: --ttl must be between 1 and 10\n");
                return -1;
            }
            cfg->ttl = t;
            break;
        }
        case OPT_NO_IPV6: cfg->ipv6    = false;        break;
        case OPT_NO_GUI:  cfg->mode    = BD_MODE_NOGUI; break;
        case OPT_TRAY:    cfg->mode    = BD_MODE_TRAY;  break;
        case OPT_VERBOSE: cfg->verbose = true;          break;
        case 'h': usage(argv[0]); exit(0);
        case 'V': printf("%s %s\n", BYEDPI_APP_NAME, BYEDPI_VERSION); exit(0);
        default:  return -1;
        }
    }
    return 0;
}

/* Warn about conditions that affect ByeDPI before we touch the firewall. */
static void preflight(bd_config *cfg)
{
    if (geteuid() != 0)
        BD_WARN("not running as root; iptables and raw sockets need "
                "CAP_NET_ADMIN + CAP_NET_RAW");

    if (bd_service_active("ufw"))
        BD_WARN("ufw is active: it may reorder or flush the OUTPUT chain and "
                "interfere with ByeDPI's NFQUEUE rules");
    if (bd_service_active("firewalld"))
        BD_WARN("firewalld is active: it may reorder or flush the OUTPUT chain "
                "and interfere with ByeDPI's NFQUEUE rules");

    cfg->resolved_active = bd_systemd_resolved_active();
    if (cfg->resolved_active)
        BD_INFO("systemd-resolved detected on port 53; DNS queries are "
                "forwarded upstream from an ephemeral local port to avoid a "
                "bind conflict");
}

/* ---- headless mode ------------------------------------------------------- */

static int run_headless(bd_config *cfg)
{
    /* Block the termination signals and wait for them synchronously so the
     * engine (and its worker threads) shut down cleanly. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    bd_engine *e = bd_engine_new(cfg);
    if (!e) {
        BD_ERR("failed to allocate engine");
        return 1;
    }
    if (bd_engine_start(e) != 0) {
        BD_ERR("failed to start engine");
        bd_engine_free(e);
        return 1;
    }

    BD_INFO("%s %s running headless. Press Ctrl-C to stop.",
            BYEDPI_APP_NAME, BYEDPI_VERSION);

    int sig = 0;
    sigwait(&set, &sig);
    BD_INFO("signal %d received, shutting down", sig);

    bd_engine_stop(e);
    bd_engine_free(e);
    return 0;
}

int main(int argc, char **argv)
{
    bd_config cfg;
    set_defaults(&cfg);

    if (parse_args(argc, argv, &cfg) != 0)
        return 2;

    bd_log_set_level(cfg.verbose ? BD_LOG_DEBUG : BD_LOG_INFO);

    preflight(&cfg);

    switch (cfg.mode) {
    case BD_MODE_NOGUI:
        return run_headless(&cfg);

    case BD_MODE_GUI:
    case BD_MODE_TRAY:
#ifdef HAVE_GUI
        return bd_gui_run(&cfg, cfg.mode == BD_MODE_TRAY);
#else
        BD_WARN("built without GUI support; falling back to headless mode");
        return run_headless(&cfg);
#endif
    }
    return 0;
}

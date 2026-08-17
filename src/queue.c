// SPDX-License-Identifier: Apache-2.0
/*
 * queue.c - The Passewall engine. Owns the netfilter queue, the raw injection
 * sockets, the firewall rules and the receive thread, and dispatches each
 * intercepted packet to the appropriate DPI-evasion handler.
 */

#include "byedpi.h"
#include "dpi.h"
#include "iptables.h"
#include "net.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct bd_engine {
    bd_config          *cfg;

    struct nfq_handle  *h;
    struct nfq_q_handle *qh;
    int                 fd;
    struct bd_injector  inj;

    pthread_t           thread;
    bool                thread_started;
    volatile bool       running;
    bool                rules_applied;

    pthread_mutex_t     lock;   /* guards stats */
    bd_stats            stats;
};

/* ---- statistics ---------------------------------------------------------- */

void bd_engine_note_split(bd_engine *e)
{
    pthread_mutex_lock(&e->lock);
    e->stats.tcp_split++;
    pthread_mutex_unlock(&e->lock);
}
void bd_engine_note_fake(bd_engine *e)
{
    pthread_mutex_lock(&e->lock);
    e->stats.fake_sent++;
    pthread_mutex_unlock(&e->lock);
}
void bd_engine_note_dns(bd_engine *e)
{
    pthread_mutex_lock(&e->lock);
    e->stats.dns_forwarded++;
    pthread_mutex_unlock(&e->lock);
}
void bd_engine_note_quic(bd_engine *e)
{
    pthread_mutex_lock(&e->lock);
    e->stats.quic_handled++;
    pthread_mutex_unlock(&e->lock);
}

void bd_engine_get_stats(bd_engine *e, bd_stats *out)
{
    pthread_mutex_lock(&e->lock);
    *out = e->stats;
    pthread_mutex_unlock(&e->lock);
}

/* ---- QUIC awareness ------------------------------------------------------ */

/* True for a QUIC long-header Initial packet. */
static bool quic_is_initial(const uint8_t *d, int len)
{
    if (len < 5)
        return false;
    /* Long header form (0x80) + fixed bit (0x40), packet type Initial (0x00). */
    if ((d[0] & 0xC0) != 0xC0)
        return false;
    if ((d[0] & 0x30) != 0x00)
        return false;
    /* A non-zero version number follows the first byte. */
    uint32_t ver = (uint32_t)d[1] << 24 | (uint32_t)d[2] << 16 |
                   (uint32_t)d[3] << 8  | d[4];
    return ver != 0;
}

/* ---- packet callback ----------------------------------------------------- */

static int packet_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa, void *data)
{
    (void)nfmsg;
    bd_engine *e = (bd_engine *)data;
    bd_config *cfg = e->cfg;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *pdata = NULL;
    int len = nfq_get_payload(nfa, &pdata);

    int verdict = NF_ACCEPT;

    if (len > 0 && pdata) {
        pthread_mutex_lock(&e->lock);
        e->stats.packets_seen++;
        pthread_mutex_unlock(&e->lock);

        struct bd_packet p;
        if (bd_packet_parse(pdata, len, &p) == 0) {
            if (p.l4proto == IPPROTO_TCP &&
                (p.dport == 80 || p.dport == 443)) {
                if (bd_tcp_handle(e, &e->inj, cfg, &p) == BD_VERDICT_DROP)
                    verdict = NF_DROP;
            } else if (p.l4proto == IPPROTO_UDP && p.dport == 53) {
                if (cfg->enable_dns &&
                    bd_dns_handle(e, &e->inj, cfg, &p) == BD_VERDICT_DROP)
                    verdict = NF_DROP;
            } else if (p.l4proto == IPPROTO_UDP && p.dport == 443) {
                if (cfg->enable_quic && quic_is_initial(p.payload, p.payload_len)) {
                    /* Drop the QUIC Initial to force the client to fall back
                     * to TLS-over-TCP, which our TCP path can defeat. */
                    if (cfg->verbose)
                        BD_DEBUG("QUIC Initial dropped (forcing TCP fallback)");
                    bd_engine_note_quic(e);
                    verdict = NF_DROP;
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

/* ---- receive loop -------------------------------------------------------- */

static void *recv_loop(void *arg)
{
    bd_engine *e = (bd_engine *)arg;
    char *buf = malloc(0x10000);
    if (!buf) {
        BD_ERR("out of memory for packet buffer");
        return NULL;
    }

    struct pollfd pfd = { .fd = e->fd, .events = POLLIN };

    while (e->running) {
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            BD_ERR("poll: %s", strerror(errno));
            break;
        }
        if (pr == 0)
            continue; /* timeout: re-check running flag */

        int n = recv(e->fd, buf, 0x10000, 0);
        if (n < 0) {
            if (errno == ENOBUFS) {
                BD_WARN("kernel packet buffer overrun (traffic burst)");
                continue;
            }
            if (errno == EINTR)
                continue;
            BD_ERR("recv: %s", strerror(errno));
            break;
        }
        if (n == 0)
            break;
        nfq_handle_packet(e->h, buf, n);
    }

    free(buf);
    return NULL;
}

/* ---- lifecycle ----------------------------------------------------------- */

bd_engine *bd_engine_new(bd_config *cfg)
{
    bd_engine *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->cfg = cfg;
    e->fd = -1;
    e->inj.fd4 = e->inj.fd6 = -1;
    pthread_mutex_init(&e->lock, NULL);
    return e;
}

int bd_engine_start(bd_engine *e)
{
    if (e->running)
        return 0;

    memset(&e->stats, 0, sizeof(e->stats));

    if (bd_injector_open(&e->inj, e->cfg->ipv6) != 0)
        return -1;

    if (bd_iptables_apply(e->cfg) != 0) {
        bd_injector_close(&e->inj);
        return -1;
    }
    e->rules_applied = true;

    e->h = nfq_open();
    if (!e->h) {
        BD_ERR("nfq_open failed (is nfnetlink_queue loaded? are you root?)");
        goto fail;
    }
    /* Unbind/bind are historically required and harmless if unsupported. */
    nfq_unbind_pf(e->h, AF_INET);
    if (nfq_bind_pf(e->h, AF_INET) < 0)
        BD_WARN("nfq_bind_pf(AF_INET) failed (continuing)");
    if (e->cfg->ipv6) {
        nfq_unbind_pf(e->h, AF_INET6);
        if (nfq_bind_pf(e->h, AF_INET6) < 0)
            BD_WARN("nfq_bind_pf(AF_INET6) failed (continuing)");
    }

    e->qh = nfq_create_queue(e->h, BYEDPI_QUEUE_NUM, &packet_cb, e);
    if (!e->qh) {
        BD_ERR("nfq_create_queue(%d) failed (queue already in use?)",
               BYEDPI_QUEUE_NUM);
        goto fail;
    }
    if (nfq_set_mode(e->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        BD_ERR("nfq_set_mode failed");
        goto fail;
    }
    nfq_set_queue_maxlen(e->qh, 4096);

    e->fd = nfq_fd(e->h);

    /* Enlarge the receive buffer to survive bursts. */
    int rcvbuf = 1 << 20;
    setsockopt(e->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    e->running = true;
    if (pthread_create(&e->thread, NULL, recv_loop, e) != 0) {
        BD_ERR("pthread_create: %s", strerror(errno));
        e->running = false;
        goto fail;
    }
    e->thread_started = true;

    BD_INFO("engine started (queue %d, ttl %d, ipv6 %s)",
            BYEDPI_QUEUE_NUM, e->cfg->ttl, e->cfg->ipv6 ? "on" : "off");
    return 0;

fail:
    if (e->qh) { nfq_destroy_queue(e->qh); e->qh = NULL; }
    if (e->h)  { nfq_close(e->h); e->h = NULL; }
    if (e->rules_applied) {
        bd_iptables_revert(e->cfg);
        e->rules_applied = false;
    }
    bd_injector_close(&e->inj);
    e->fd = -1;
    return -1;
}

void bd_engine_stop(bd_engine *e)
{
    if (!e->running && !e->thread_started)
        return;

    e->running = false;
    if (e->thread_started) {
        pthread_join(e->thread, NULL);
        e->thread_started = false;
    }

    if (e->qh) { nfq_destroy_queue(e->qh); e->qh = NULL; }
    if (e->h)  { nfq_close(e->h); e->h = NULL; }
    e->fd = -1;

    if (e->rules_applied) {
        bd_iptables_revert(e->cfg);
        e->rules_applied = false;
    }
    bd_injector_close(&e->inj);

    BD_INFO("engine stopped");
}

bool bd_engine_is_running(bd_engine *e)
{
    return e && e->running;
}

void bd_engine_free(bd_engine *e)
{
    if (!e)
        return;
    bd_engine_stop(e);
    pthread_mutex_destroy(&e->lock);
    free(e);
}

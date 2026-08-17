// SPDX-License-Identifier: Apache-2.0
/*
 * dns.c - DNS interception. Outbound UDP/53 queries are captured, forwarded
 * to a configurable upstream resolver (with fallback) from a background
 * worker, and the answer is injected back to the originating socket. The
 * original query is dropped.
 */

#include "dpi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define BD_DNS_MAX      2048
#define BD_DNS_TIMEOUT_MS 900

struct dns_job {
    const struct bd_injector *inj;
    bd_engine               *engine;

    struct bd_endpoint       src;   /* querying host   */
    struct bd_endpoint       dst;   /* resolver the app targeted */
    uint16_t                 sport;
    uint16_t                 dport;

    char                     upstream[64];
    char                     fallback[64];
    int                      upstream_port;

    int                      qlen;
    uint8_t                  query[BD_DNS_MAX];
};

/* Send `query` to `server:port` and read a reply into `out`. Returns the
 * reply length, or -1 on timeout/error. */
static int dns_query_upstream(const char *server, int port,
                              const uint8_t *query, int qlen,
                              uint8_t *out, int outcap)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    int family;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, server, &a4) == 1) {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss;
        memset(s, 0, sizeof(*s));
        s->sin_family = AF_INET;
        s->sin_port   = htons((uint16_t)port);
        s->sin_addr   = a4;
        sslen  = sizeof(*s);
        family = AF_INET;
    } else if (inet_pton(AF_INET6, server, &a6) == 1) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
        memset(s, 0, sizeof(*s));
        s->sin6_family = AF_INET6;
        s->sin6_port   = htons((uint16_t)port);
        s->sin6_addr   = a6;
        sslen  = sizeof(*s);
        family = AF_INET6;
    } else {
        return -1;
    }

    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    /* Mark our own upstream query so it skips the NFQUEUE rules. Without this
     * the query to the upstream resolver (also UDP/53) would be intercepted by
     * our own queue and re-forwarded endlessly, exhausting file descriptors. */
    int mark = BYEDPI_FWMARK;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        BD_WARN("DNS upstream SO_MARK: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int rc = -1;
    if (sendto(fd, query, qlen, 0, (struct sockaddr *)&ss, sslen) == qlen) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {
            .tv_sec  = BD_DNS_TIMEOUT_MS / 1000,
            .tv_usec = (BD_DNS_TIMEOUT_MS % 1000) * 1000,
        };
        if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0) {
            ssize_t n = recv(fd, out, outcap, 0);
            if (n > 0)
                rc = (int)n;
        }
    }
    close(fd);
    return rc;
}

static void *dns_worker(void *arg)
{
    struct dns_job *j = (struct dns_job *)arg;
    uint8_t reply[BD_DNS_MAX];

    int rlen = dns_query_upstream(j->upstream, j->upstream_port,
                                  j->query, j->qlen, reply, sizeof(reply));
    if (rlen < 0 && j->fallback[0]) {
        rlen = dns_query_upstream(j->fallback, j->upstream_port,
                                  j->query, j->qlen, reply, sizeof(reply));
    }

    if (rlen > 0) {
        /* Inject the reply as though it came straight from the resolver the
         * application originally addressed. */
        if (bd_send_udp(j->inj, &j->dst, j->dport, &j->src, j->sport,
                        64, reply, rlen) == 0) {
            bd_engine_note_dns(j->engine);
        } else {
            BD_DEBUG("DNS reply injection failed");
        }
    } else {
        BD_WARN("DNS upstream query failed (%s / %s)", j->upstream, j->fallback);
    }

    free(j);
    return NULL;
}

int bd_dns_handle(bd_engine *e, const struct bd_injector *inj,
                  const bd_config *cfg, const struct bd_packet *p)
{
    if (p->payload_len <= 0 || p->payload_len > BD_DNS_MAX)
        return BD_VERDICT_ACCEPT;

    /* IPv6 upstream injection requires the v6 raw socket; if it is absent we
     * cannot spoof a v6 reply, so let the query pass unmodified. */
    if (p->src.family == AF_INET6 && inj->fd6 < 0)
        return BD_VERDICT_ACCEPT;

    struct dns_job *j = calloc(1, sizeof(*j));
    if (!j)
        return BD_VERDICT_ACCEPT;

    j->inj    = inj;
    j->engine = e;
    j->src    = p->src;
    j->dst    = p->dst;
    j->sport  = p->sport;
    j->dport  = p->dport;
    j->upstream_port = cfg->dns_upstream_port > 0 ? cfg->dns_upstream_port : 53;
    snprintf(j->upstream, sizeof(j->upstream), "%s", cfg->dns_addr);
    snprintf(j->fallback, sizeof(j->fallback), "%s", cfg->dns_fallback);
    j->qlen = p->payload_len;
    memcpy(j->query, p->payload, p->payload_len);

    pthread_t tid;
    if (pthread_create(&tid, NULL, dns_worker, j) != 0) {
        free(j);
        return BD_VERDICT_ACCEPT;
    }
    pthread_detach(tid);

    return BD_VERDICT_DROP;
}

// SPDX-License-Identifier: Apache-2.0
/*
 * tcp.c - The core TCP DPI-evasion routine: fake low-TTL duplicate followed
 * by fragmented real data. Equivalent to GoodbyeDPI's combined "-5" mode.
 */

#include "dpi.h"
#include <netinet/tcp.h>
#include <string.h>

/* Normal outbound hop limit for the *real* fragments. */
#define BD_REAL_TTL 64

/* TCP flag bits. */
#define BD_TH_FIN 0x01
#define BD_TH_SYN 0x02
#define BD_TH_RST 0x04
#define BD_TH_PSH 0x08
#define BD_TH_ACK 0x10

int bd_tcp_handle(bd_engine *e, const struct bd_injector *inj,
                  const bd_config *cfg, const struct bd_packet *p)
{
    /* We only rewrite payload-bearing segments. Control segments (SYN, pure
     * ACK, FIN, RST) pass through untouched. */
    if (p->payload_len <= 0)
        return BD_VERDICT_ACCEPT;
    if (p->tcp_flags & (BD_TH_SYN | BD_TH_RST | BD_TH_FIN))
        return BD_VERDICT_ACCEPT;

    const uint8_t *data = p->payload;
    int len = p->payload_len;

    /* Decide whether this is a packet we should tamper with, and where to
     * split it. We only touch the first application record (HTTP request or
     * TLS ClientHello) so that bulk transfers are left alone. */
    int split = -1;
    bool interesting = false;

    if (p->dport == 443) {
        if (cfg->enable_tls && bd_tls_is_clienthello(data, len)) {
            interesting = true;
            split = bd_tls_split_offset(data, len);
        }
    } else if (p->dport == 80) {
        if (cfg->enable_http && bd_http_is_request(data, len)) {
            interesting = true;
            split = bd_http_split_offset(data, len);
        }
    }

    if (!interesting)
        return BD_VERDICT_ACCEPT;

    /* Fall back to the generic "split at byte 2" rule when no protocol
     * specific boundary was found. */
    if (split <= 0 || split >= len)
        split = (len > 2) ? 2 : 1;
    if (split >= len)
        return BD_VERDICT_ACCEPT; /* too small to split usefully */

    char sb[INET6_ADDRSTRLEN], db[INET6_ADDRSTRLEN];
    if (cfg->verbose) {
        BD_DEBUG("TCP %s:%u -> %s:%u  len=%d split=%d proto=%s",
                 bd_endpoint_str(&p->src, sb, sizeof(sb)), p->sport,
                 bd_endpoint_str(&p->dst, db, sizeof(db)), p->dport,
                 len, split, p->dport == 443 ? "TLS" : "HTTP");
    }

    uint8_t flags_ack  = (uint8_t)(p->tcp_flags & ~BD_TH_PSH);
    uint8_t flags_full = p->tcp_flags;

    /*
     * 1) Fake duplicate: the full real payload at the original sequence
     *    number but with a short TTL so it expires past the DPI box and
     *    never reaches the server. This poisons stateful DPI reassembly.
     */
    if (bd_send_tcp(inj, &p->src, p->sport, &p->dst, p->dport,
                    p->seq, p->ack, flags_full, p->window,
                    cfg->ttl, data, len) == 0) {
        bd_engine_note_fake(e);
    }

    /*
     * 2) Real data, fragmented into two segments with a normal TTL.
     */
    int rc1 = bd_send_tcp(inj, &p->src, p->sport, &p->dst, p->dport,
                          p->seq, p->ack, flags_ack, p->window,
                          BD_REAL_TTL, data, split);

    int rc2 = bd_send_tcp(inj, &p->src, p->sport, &p->dst, p->dport,
                          p->seq + (uint32_t)split, p->ack, flags_full,
                          p->window, BD_REAL_TTL,
                          data + split, len - split);

    if (rc1 != 0 || rc2 != 0) {
        /* Injection failed; let the kernel send the original instead so the
         * connection is not stalled. */
        BD_WARN("fragment injection failed, passing packet through");
        return BD_VERDICT_ACCEPT;
    }

    bd_engine_note_split(e);
    return BD_VERDICT_DROP;
}

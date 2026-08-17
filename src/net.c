// SPDX-License-Identifier: Apache-2.0
/*
 * net.c - Packet parsing, checksums and raw-socket injection for both
 * IPv4 and IPv6. All crafted packets are fully assembled in user space and
 * sent through an IP_HDRINCL / IPV6_HDRINCL raw socket.
 */

#include "net.h"
#include "byedpi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif

/* ---- checksum helpers ---------------------------------------------------- */

static uint32_t csum_accumulate(const void *buf, int len, uint32_t sum)
{
    const uint16_t *w = (const uint16_t *)buf;
    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)w;
        sum += last;
    }
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* IPv4 pseudo-header checksum over an L4 (TCP/UDP) segment. The pseudo-header
 * is assembled in a flat byte buffer (network byte order) so the checksum is
 * computed identically to the way the L4 header and payload are summed. */
static uint16_t l4_checksum4(const struct in_addr *src, const struct in_addr *dst,
                             uint8_t proto, const void *l4, int l4len)
{
    uint8_t ph[12];
    memcpy(ph + 0, &src->s_addr, 4);
    memcpy(ph + 4, &dst->s_addr, 4);
    ph[8] = 0;
    ph[9] = proto;
    uint16_t len_be = htons((uint16_t)l4len);
    memcpy(ph + 10, &len_be, 2);

    uint32_t sum = csum_accumulate(ph, sizeof(ph), 0);
    sum = csum_accumulate(l4, l4len, sum);
    return csum_fold(sum);
}

/* IPv6 pseudo-header checksum over an L4 (TCP/UDP) segment. */
static uint16_t l4_checksum6(const struct in6_addr *src, const struct in6_addr *dst,
                             uint8_t proto, const void *l4, int l4len)
{
    uint8_t ph[40];
    memcpy(ph + 0,  src, 16);
    memcpy(ph + 16, dst, 16);
    uint32_t len_be = htonl((uint32_t)l4len);
    memcpy(ph + 32, &len_be, 4);
    ph[36] = 0;
    ph[37] = 0;
    ph[38] = 0;
    ph[39] = proto;

    uint32_t sum = csum_accumulate(ph, sizeof(ph), 0);
    sum = csum_accumulate(l4, l4len, sum);
    return csum_fold(sum);
}

/* ---- injector ------------------------------------------------------------ */

int bd_injector_open(struct bd_injector *inj, int want_ipv6)
{
    inj->fd4 = -1;
    inj->fd6 = -1;

    inj->fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (inj->fd4 < 0) {
        BD_ERR("raw IPv4 socket: %s (need CAP_NET_RAW / root)", strerror(errno));
        return -1;
    }
    int on = 1;
    if (setsockopt(inj->fd4, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        BD_ERR("IP_HDRINCL: %s", strerror(errno));
        close(inj->fd4);
        inj->fd4 = -1;
        return -1;
    }
    /* Stamp our fwmark so the injected packets skip the NFQUEUE rules. */
    int mark = BYEDPI_FWMARK;
    if (setsockopt(inj->fd4, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
        BD_WARN("SO_MARK(v4): %s (injected packets may re-enter the queue)",
                strerror(errno));

    if (want_ipv6) {
        inj->fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (inj->fd6 < 0) {
            BD_WARN("raw IPv6 socket: %s (IPv6 injection disabled)", strerror(errno));
        } else {
            int on6 = 1;
            if (setsockopt(inj->fd6, IPPROTO_IPV6, IPV6_HDRINCL,
                           &on6, sizeof(on6)) < 0) {
                BD_WARN("IPV6_HDRINCL: %s (IPv6 injection disabled)", strerror(errno));
                close(inj->fd6);
                inj->fd6 = -1;
            } else {
                int mark6 = BYEDPI_FWMARK;
                if (setsockopt(inj->fd6, SOL_SOCKET, SO_MARK,
                               &mark6, sizeof(mark6)) < 0)
                    BD_WARN("SO_MARK(v6): %s", strerror(errno));
            }
        }
    }
    return 0;
}

void bd_injector_close(struct bd_injector *inj)
{
    if (inj->fd4 >= 0) close(inj->fd4);
    if (inj->fd6 >= 0) close(inj->fd6);
    inj->fd4 = inj->fd6 = -1;
}

/* ---- parsing ------------------------------------------------------------- */

int bd_packet_parse(const uint8_t *data, int len, struct bd_packet *p)
{
    if (len < 1)
        return -1;
    memset(p, 0, sizeof(*p));
    p->raw     = data;
    p->raw_len = len;

    int version = data[0] >> 4;
    const uint8_t *l4;
    int l4len;

    if (version == 4) {
        if (len < (int)sizeof(struct iphdr))
            return -1;
        const struct iphdr *ip = (const struct iphdr *)data;
        int ihl = ip->ihl * 4;
        if (ihl < (int)sizeof(struct iphdr) || len < ihl)
            return -1;

        p->family     = AF_INET;
        p->l3_hdr_len = ihl;
        p->l4proto    = ip->protocol;
        p->src.family = AF_INET;
        p->dst.family = AF_INET;
        memcpy(p->src.addr, &ip->saddr, 4);
        memcpy(p->dst.addr, &ip->daddr, 4);

        l4    = data + ihl;
        l4len = len - ihl;
    } else if (version == 6) {
        if (len < (int)sizeof(struct ip6_hdr))
            return -1;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)data;

        p->family     = AF_INET6;
        p->l3_hdr_len = sizeof(struct ip6_hdr);
        p->l4proto    = ip6->ip6_nxt; /* extension headers not handled */
        p->src.family = AF_INET6;
        p->dst.family = AF_INET6;
        memcpy(p->src.addr, &ip6->ip6_src, 16);
        memcpy(p->dst.addr, &ip6->ip6_dst, 16);

        l4    = data + sizeof(struct ip6_hdr);
        l4len = len - (int)sizeof(struct ip6_hdr);
    } else {
        return -1;
    }

    if (p->l4proto == IPPROTO_TCP) {
        if (l4len < (int)sizeof(struct tcphdr))
            return -1;
        const struct tcphdr *th = (const struct tcphdr *)l4;
        int doff = th->doff * 4;
        if (doff < (int)sizeof(struct tcphdr) || l4len < doff)
            return -1;

        p->sport       = ntohs(th->source);
        p->dport       = ntohs(th->dest);
        p->seq         = ntohl(th->seq);
        p->ack         = ntohl(th->ack_seq);
        p->window      = ntohs(th->window);
        p->tcp_flags   = ((const uint8_t *)th)[13];
        p->payload     = l4 + doff;
        p->payload_len = l4len - doff;
    } else if (p->l4proto == IPPROTO_UDP) {
        if (l4len < (int)sizeof(struct udphdr))
            return -1;
        const struct udphdr *uh = (const struct udphdr *)l4;
        p->sport       = ntohs(uh->source);
        p->dport       = ntohs(uh->dest);
        p->payload     = l4 + sizeof(struct udphdr);
        p->payload_len = l4len - (int)sizeof(struct udphdr);
        if (p->payload_len < 0)
            p->payload_len = 0;
    } else {
        return -1;
    }
    return 0;
}

/* ---- injection ----------------------------------------------------------- */

#define BD_MAX_FRAME 2048

static int send_frame4(const struct bd_injector *inj, const uint8_t *frame,
                       int total, const struct in_addr *dst)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr   = *dst;

    ssize_t n = sendto(inj->fd4, frame, total, 0,
                       (struct sockaddr *)&sin, sizeof(sin));
    if (n < 0) {
        BD_DEBUG("sendto(v4): %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int send_frame6(const struct bd_injector *inj, const uint8_t *frame,
                       int total, const struct in6_addr *dst)
{
    if (inj->fd6 < 0)
        return -1;
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    memcpy(&sin6.sin6_addr, dst, 16);

    ssize_t n = sendto(inj->fd6, frame, total, 0,
                       (struct sockaddr *)&sin6, sizeof(sin6));
    if (n < 0) {
        BD_DEBUG("sendto(v6): %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Build an L4 buffer (header + payload) shared by both address families. */
static int build_tcp_l4(uint8_t *buf, uint16_t sport, uint16_t dport,
                        uint32_t seq, uint32_t ack, uint8_t flags,
                        uint16_t window, const uint8_t *payload, int paylen)
{
    struct tcphdr *th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));
    th->source  = htons(sport);
    th->dest    = htons(dport);
    th->seq     = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff    = 5;
    ((uint8_t *)th)[13] = flags;
    th->window  = htons(window);
    th->check   = 0;
    th->urg_ptr = 0;
    if (paylen > 0)
        memcpy(buf + sizeof(struct tcphdr), payload, paylen);
    return (int)sizeof(struct tcphdr) + paylen;
}

static int build_udp_l4(uint8_t *buf, uint16_t sport, uint16_t dport,
                        const uint8_t *payload, int paylen)
{
    struct udphdr *uh = (struct udphdr *)buf;
    uh->source = htons(sport);
    uh->dest   = htons(dport);
    uh->len    = htons((uint16_t)(sizeof(struct udphdr) + paylen));
    uh->check  = 0;
    if (paylen > 0)
        memcpy(buf + sizeof(struct udphdr), payload, paylen);
    return (int)sizeof(struct udphdr) + paylen;
}

static int inject4(const struct bd_injector *inj,
                   const struct bd_endpoint *src, const struct bd_endpoint *dst,
                   uint8_t proto, int ttl, const uint8_t *l4, int l4len)
{
    uint8_t frame[BD_MAX_FRAME];
    int total = (int)sizeof(struct iphdr) + l4len;
    if (total > BD_MAX_FRAME)
        return -1;

    struct iphdr *ip = (struct iphdr *)frame;
    memset(ip, 0, sizeof(*ip));
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons((uint16_t)total);
    ip->id       = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = htons(0x4000); /* Don't Fragment */
    ip->ttl      = (uint8_t)ttl;
    ip->protocol = proto;
    memcpy(&ip->saddr, src->addr, 4);
    memcpy(&ip->daddr, dst->addr, 4);
    ip->check    = 0;
    ip->check    = csum_fold(csum_accumulate(ip, sizeof(*ip), 0));

    memcpy(frame + sizeof(struct iphdr), l4, l4len);

    /* L4 checksum with pseudo-header. */
    struct in_addr s = { .s_addr = ip->saddr };
    struct in_addr d = { .s_addr = ip->daddr };
    uint16_t cks = l4_checksum4(&s, &d, proto, frame + sizeof(struct iphdr), l4len);
    if (proto == IPPROTO_TCP)
        ((struct tcphdr *)(frame + sizeof(struct iphdr)))->check = cks;
    else
        ((struct udphdr *)(frame + sizeof(struct iphdr)))->check = cks ? cks : 0xffff;

    return send_frame4(inj, frame, total, &d);
}

static int inject6(const struct bd_injector *inj,
                   const struct bd_endpoint *src, const struct bd_endpoint *dst,
                   uint8_t proto, int ttl, const uint8_t *l4, int l4len)
{
    uint8_t frame[BD_MAX_FRAME];
    int total = (int)sizeof(struct ip6_hdr) + l4len;
    if (total > BD_MAX_FRAME)
        return -1;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)frame;
    memset(ip6, 0, sizeof(*ip6));
    ip6->ip6_flow = htonl(6u << 28);
    ip6->ip6_plen = htons((uint16_t)l4len);
    ip6->ip6_nxt  = proto;
    ip6->ip6_hlim = (uint8_t)ttl;
    memcpy(&ip6->ip6_src, src->addr, 16);
    memcpy(&ip6->ip6_dst, dst->addr, 16);

    memcpy(frame + sizeof(struct ip6_hdr), l4, l4len);

    uint16_t cks = l4_checksum6(&ip6->ip6_src, &ip6->ip6_dst, proto,
                                frame + sizeof(struct ip6_hdr), l4len);
    if (proto == IPPROTO_TCP)
        ((struct tcphdr *)(frame + sizeof(struct ip6_hdr)))->check = cks;
    else
        ((struct udphdr *)(frame + sizeof(struct ip6_hdr)))->check = cks ? cks : 0xffff;

    struct in6_addr d;
    memcpy(&d, dst->addr, 16);
    return send_frame6(inj, frame, total, &d);
}

int bd_send_tcp(const struct bd_injector *inj,
                const struct bd_endpoint *src, uint16_t sport,
                const struct bd_endpoint *dst, uint16_t dport,
                uint32_t seq, uint32_t ack, uint8_t flags,
                uint16_t window, int ttl,
                const uint8_t *payload, int paylen)
{
    if (paylen < 0)
        paylen = 0;
    uint8_t l4[BD_MAX_FRAME];
    if ((int)sizeof(struct tcphdr) + paylen > BD_MAX_FRAME)
        return -1;
    int l4len = build_tcp_l4(l4, sport, dport, seq, ack, flags, window, payload, paylen);

    if (src->family == AF_INET)
        return inject4(inj, src, dst, IPPROTO_TCP, ttl, l4, l4len);
    return inject6(inj, src, dst, IPPROTO_TCP, ttl, l4, l4len);
}

int bd_send_udp(const struct bd_injector *inj,
                const struct bd_endpoint *src, uint16_t sport,
                const struct bd_endpoint *dst, uint16_t dport,
                int ttl, const uint8_t *payload, int paylen)
{
    if (paylen < 0)
        paylen = 0;
    uint8_t l4[BD_MAX_FRAME];
    if ((int)sizeof(struct udphdr) + paylen > BD_MAX_FRAME)
        return -1;
    int l4len = build_udp_l4(l4, sport, dport, payload, paylen);

    if (src->family == AF_INET)
        return inject4(inj, src, dst, IPPROTO_UDP, ttl, l4, l4len);
    return inject6(inj, src, dst, IPPROTO_UDP, ttl, l4, l4len);
}

const char *bd_endpoint_str(const struct bd_endpoint *ep, char *buf, size_t n)
{
    if (ep->family == AF_INET)
        inet_ntop(AF_INET, ep->addr, buf, (socklen_t)n);
    else
        inet_ntop(AF_INET6, ep->addr, buf, (socklen_t)n);
    return buf;
}

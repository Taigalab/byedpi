// SPDX-License-Identifier: Apache-2.0
/*
 * net.h - Low level packet crafting, parsing and raw-socket injection.
 */

#ifndef BYEDPI_NET_H
#define BYEDPI_NET_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* A family-agnostic L3 address held in network byte order. */
struct bd_endpoint {
    int     family;      /* AF_INET or AF_INET6 */
    uint8_t addr[16];    /* IPv4 uses the first 4 bytes */
};

/* Raw sockets used to inject crafted packets back onto the wire. */
struct bd_injector {
    int fd4;             /* AF_INET,  IPPROTO_RAW, IP_HDRINCL   */
    int fd6;             /* AF_INET6, IPPROTO_RAW, IPV6_HDRINCL */
};

/* Parsed view of an intercepted packet. Pointers alias the NFQUEUE buffer. */
struct bd_packet {
    int             family;
    const uint8_t  *raw;
    int             raw_len;
    int             l3_hdr_len;
    uint8_t         l4proto;      /* IPPROTO_TCP or IPPROTO_UDP */

    struct bd_endpoint src;
    struct bd_endpoint dst;
    uint16_t        sport;
    uint16_t        dport;

    /* TCP only */
    uint32_t        seq;
    uint32_t        ack;
    uint8_t         tcp_flags;
    uint16_t        window;

    const uint8_t  *payload;
    int             payload_len;
};

int  bd_injector_open(struct bd_injector *inj, int want_ipv6);
void bd_injector_close(struct bd_injector *inj);

/* Parse an IPv4/IPv6 TCP or UDP packet. Returns 0 on success, -1 otherwise. */
int  bd_packet_parse(const uint8_t *data, int len, struct bd_packet *p);

/* Craft and inject a single TCP segment. Returns 0 on success. */
int  bd_send_tcp(const struct bd_injector *inj,
                 const struct bd_endpoint *src, uint16_t sport,
                 const struct bd_endpoint *dst, uint16_t dport,
                 uint32_t seq, uint32_t ack, uint8_t flags,
                 uint16_t window, int ttl,
                 const uint8_t *payload, int paylen);

/* Craft and inject a single UDP datagram. Returns 0 on success. */
int  bd_send_udp(const struct bd_injector *inj,
                 const struct bd_endpoint *src, uint16_t sport,
                 const struct bd_endpoint *dst, uint16_t dport,
                 int ttl, const uint8_t *payload, int paylen);

/* Format an endpoint as text (for logging). buf must hold >= INET6_ADDRSTRLEN. */
const char *bd_endpoint_str(const struct bd_endpoint *ep, char *buf, size_t n);

#endif /* BYEDPI_NET_H */

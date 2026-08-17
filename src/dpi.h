// SPDX-License-Identifier: Apache-2.0
/*
 * dpi.h - DPI-evasion primitives: split-point detection (HTTP/TLS),
 * TCP fragmentation + fake injection, and DNS interception.
 */

#ifndef BYEDPI_DPI_H
#define BYEDPI_DPI_H

#include "byedpi.h"
#include "net.h"

/* Verdicts returned to the queue callback. */
#define BD_VERDICT_ACCEPT 0
#define BD_VERDICT_DROP   1

/* Returns true if the buffer starts with a plausible HTTP request line. */
bool bd_http_is_request(const uint8_t *data, int len);

/*
 * Offset (within the HTTP payload) at which to split so that the "Host"
 * header is fragmented across two segments. Returns -1 if no split point
 * could be found.
 */
int bd_http_split_offset(const uint8_t *data, int len);

/* Returns true if the buffer looks like a TLS handshake record (ClientHello). */
bool bd_tls_is_clienthello(const uint8_t *data, int len);

/*
 * Offset (within the TLS payload) at which to split so that the SNI host
 * name is fragmented. Returns -1 if no ClientHello/SNI was found.
 */
int bd_tls_split_offset(const uint8_t *data, int len);

/*
 * Handle an intercepted outbound TCP data packet: inject a low-TTL fake
 * duplicate, then re-send the real data as two fragments, and DROP the
 * original. Returns BD_VERDICT_DROP if it acted, BD_VERDICT_ACCEPT otherwise.
 */
int bd_tcp_handle(bd_engine *e, const struct bd_injector *inj,
                  const bd_config *cfg, const struct bd_packet *p);

/*
 * Handle an intercepted outbound UDP/53 DNS query: forward to the configured
 * upstream on a background worker and inject the reply back to the origin.
 * Always returns BD_VERDICT_DROP for a valid query (BD_VERDICT_ACCEPT if the
 * packet is not a forwardable query).
 */
int bd_dns_handle(bd_engine *e, const struct bd_injector *inj,
                  const bd_config *cfg, const struct bd_packet *p);

/* Count-only hook for engine statistics (implemented in queue.c). */
void bd_engine_note_split(bd_engine *e);
void bd_engine_note_fake(bd_engine *e);
void bd_engine_note_dns(bd_engine *e);
void bd_engine_note_quic(bd_engine *e);

#endif /* BYEDPI_DPI_H */

// SPDX-License-Identifier: Apache-2.0
/*
 * tls.c - Minimal TLS ClientHello parser used to locate the SNI host name so
 * the record can be split at the SNI boundary.
 */

#include "dpi.h"
#include <arpa/inet.h>
#include <string.h>

#define TLS_CONTENT_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO   0x01
#define TLS_EXT_SNI           0x0000

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

bool bd_tls_is_clienthello(const uint8_t *data, int len)
{
    if (len < 6)
        return false;
    if (data[0] != TLS_CONTENT_HANDSHAKE)
        return false;
    /* data[1..2] = record version (0x0301..0x0303) */
    if (data[1] != 0x03)
        return false;
    if (data[5] != TLS_HS_CLIENT_HELLO)
        return false;
    return true;
}

/*
 * Walk the ClientHello and return the absolute offset (within the TLS
 * payload) of the SNI host-name bytes. Returns -1 on any parse failure.
 */
int bd_tls_split_offset(const uint8_t *data, int len)
{
    if (!bd_tls_is_clienthello(data, len))
        return -1;

    int pos = 5;                    /* skip record header (5 bytes) */
    if (pos + 4 > len) return -1;
    /* handshake header: type(1) + length(3) */
    pos += 4;

    if (pos + 2 > len) return -1;   /* client_version */
    pos += 2;

    if (pos + 32 > len) return -1;  /* random */
    pos += 32;

    if (pos + 1 > len) return -1;   /* session_id */
    int sid = data[pos];
    pos += 1 + sid;
    if (pos > len) return -1;

    if (pos + 2 > len) return -1;   /* cipher_suites */
    int cs = rd16(data + pos);
    pos += 2 + cs;
    if (pos > len) return -1;

    if (pos + 1 > len) return -1;   /* compression_methods */
    int cm = data[pos];
    pos += 1 + cm;
    if (pos > len) return -1;

    if (pos + 2 > len) return -1;   /* extensions length */
    int ext_total = rd16(data + pos);
    pos += 2;
    int ext_end = pos + ext_total;
    if (ext_end > len)
        ext_end = len;

    while (pos + 4 <= ext_end) {
        int etype = rd16(data + pos);
        int elen  = rd16(data + pos + 2);
        int ebody = pos + 4;
        if (ebody + elen > ext_end)
            return -1;

        if (etype == TLS_EXT_SNI) {
            /* server_name_list: list_len(2) then entries */
            int q = ebody;
            if (q + 2 > ebody + elen) return -1;
            q += 2;                                   /* list length */
            if (q + 3 > ebody + elen) return -1;
            /* entry: type(1) + name_len(2) + name */
            q += 1;                                   /* name type */
            int name_len = rd16(data + q);
            q += 2;                                   /* now at host name */
            if (q + name_len > len || name_len <= 0)
                return -1;
            /* Split one byte into the host name so the SNI itself straddles
             * the segment boundary. */
            int off = q + 1;
            if (off > 0 && off < len)
                return off;
            if (q > 0 && q < len)
                return q;
            return -1;
        }
        pos = ebody + elen;
    }
    return -1;
}

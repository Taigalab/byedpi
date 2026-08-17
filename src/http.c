// SPDX-License-Identifier: Apache-2.0
/*
 * http.c - Detection of HTTP requests and location of the Host header so it
 * can be fragmented across two TCP segments.
 */

#include "dpi.h"
#include <string.h>
#include <strings.h>

static const char *const kMethods[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
    "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ", NULL
};

bool bd_http_is_request(const uint8_t *data, int len)
{
    if (len < 5)
        return false;
    for (int i = 0; kMethods[i]; i++) {
        size_t mlen = strlen(kMethods[i]);
        if ((size_t)len >= mlen && memcmp(data, kMethods[i], mlen) == 0)
            return true;
    }
    return false;
}

/* Case-insensitive search for "\r\nHost:" (or a leading "Host:"). */
int bd_http_split_offset(const uint8_t *data, int len)
{
    if (!bd_http_is_request(data, len))
        return -1;

    const char needle[] = "host:";
    const int nlen = 5;

    for (int i = 0; i + nlen <= len; i++) {
        /* Header names begin at start of a line. */
        bool line_start = (i == 0) || (data[i - 1] == '\n');
        if (!line_start)
            continue;
        if (strncasecmp((const char *)(data + i), needle, nlen) == 0) {
            /* Split inside the header name so "Ho" | "st: ..." land in
             * different segments. Ensure the offset stays in range. */
            int off = i + 2;
            if (off > 0 && off < len)
                return off;
            return -1;
        }
    }
    return -1;
}

/**
 * @file
 * Utility functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include "util.h"

/**
 * Prefix for Base64 secret encoding
 */
const char   BASE64_PREFIX[]   = "$base64$";
/**
 * Length of prefix for Base64 secret encoding
 */
const size_t BASE64_PREFIX_LEN = sizeof(BASE64_PREFIX) - 1;

/**
 * Base64 alphabet (RFC 4648)
 */
static const char BASE64_ALPHA[65] = "ABCDEFGHIJKLMNOP"
                                     "QRSTUVWXYZabcdef"
                                     "ghijklmnopqrstuv"
                                     "wxyz0123456789+/"
                                     "=";

/**
 * Parse user specified as a numeric UID or user name.
 *
 * @param user user name or numeric UID.
 * @return decoded UID.
 */
uid_t util_parse_user(const char *user)
{
    unsigned long uid;
    char *ep = NULL;

    uid = strtoul(user, &ep, 0);
    if (ep == NULL || *ep != '\0')
    {
        struct passwd *u = getpwnam(user);
        if (u == NULL)
            return (uid_t)-1;
        return u->pw_uid;
    }
    return uid;
}

/**
 * Parse group specified as a numeric GID or group name.
 *
 * @param group group name or numeric GID.
 * @return decoded GID.
 */
gid_t util_parse_group(const char *group)
{
    unsigned long gid;
    char *ep = NULL;

    gid = strtoul(group, &ep, 0);
    if (ep == NULL || *ep != '\0')
    {
        struct group *g = getgrnam(group);
        if (g == NULL)
            return (gid_t)-1;
        return g->gr_gid;
    }
    return gid;
}

/**
 * IPv4/IPv6 address and port to textual representation.
 *
 * @param addr    IP socket address.
 * @param addrlen socket address length.
 * @param buffer  buffer for text.
 * @param bufsize buffer size.
 * @return number of characters written, or -1 on error.
 */
int util_decode_addr(const struct sockaddr *addr, socklen_t addrlen,
                     char *buffer, size_t bufsize)
{
    char host[INET6_ADDRSTRLEN + 1] = "???", serv[16] = "?";

    getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
                NI_NUMERICHOST|NI_NUMERICSERV);
    return snprintf(buffer, bufsize,
        ((addr->sa_family == AF_INET) ? "%s:%s" : "[%s]:%s"), host, serv);
}

/**
 * IPv4/IPv6 network to textual representation.
 *
 * @param addr    IP network addrsss.
 * @param addrlen network address length.
 * @param bits    network bitmask width.
 * @param buffer  buffer for text.
 * @param bufsize buffer size.
 * @return number of characters written, or -1 on error.
 */
int util_decode_network(const struct sockaddr *addr, socklen_t addrlen,
                        unsigned bits, char *buffer, size_t bufsize)
{
    char host[INET6_ADDRSTRLEN + 1] = "???";

    if (addr->sa_family == AF_UNSPEC && bits == 0)
        return snprintf(buffer, bufsize, "*/0");
    getnameinfo(addr, addrlen, host, sizeof(host), NULL, 0,
                NI_NUMERICHOST);
    return snprintf(buffer, bufsize,
        ((addr->sa_family == AF_INET) ? "%s/%u" : "[%s]/%u"), host, bits);
}

/**
 * Encode data to Base64.
 *
 * Note that the result is not NUL-terminated.
 *
 * @param data    data to encode.
 * @param datalen data length.
 * @param buffer  buffer for Base64.
 * @param bufsize buffer size.
 * @return number of characters written, or -1 on error.
 */
ssize_t util_base64_encode(const void *data, size_t datalen, char *buffer, size_t bufsize)
{
    const unsigned char *dptr = data;
    size_t reslen = 0;
    uint32_t triplet = 0;
    int cnt = 0;

    for (; datalen > 0; datalen--)
    {
        triplet = (triplet << 8)|(*dptr++);
        if (++cnt == 3)
        {
            if ((bufsize - reslen) < 4)
                return -1;
            *buffer++ = BASE64_ALPHA[(triplet >> 18) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet >> 12) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet >>  6) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet      ) & 0x3F];
            reslen += 4;
            triplet = 0;
            cnt = 0;
        }
    }
    if (cnt != 0)
    {
        if ((bufsize - reslen) < 4)
            return -1;
        if (cnt == 2)
        {
            *buffer++ = BASE64_ALPHA[(triplet >> 10) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet >>  4) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet <<  2) & 0x3F];
            *buffer++ = BASE64_ALPHA[64];
        }
        else // if (cnt == 1)
        {
            *buffer++ = BASE64_ALPHA[(triplet >>  2) & 0x3F];
            *buffer++ = BASE64_ALPHA[(triplet <<  4) & 0x3F];
            *buffer++ = BASE64_ALPHA[64];
            *buffer++ = BASE64_ALPHA[64];
        }
        reslen += 4;
    }
    return reslen;
}

/**
 * Decode from Base64.
 *
 * @param text    Base64 text (NUL-terminated).
 * @param buffer  buffer for data.
 * @param bufsize buffer size.
 * @return number of data bytes, or -1 on error.
 */
ssize_t util_base64_decode(const char *text, void *buffer, size_t bufsize)
{
    unsigned char *rptr = buffer;
    size_t rlen = 0;
    uint32_t prefix = 0;
    int bits = 0;

    // We don't actually test whether the original encoding was correct;
    // we'd accept, e.g., "AAAA=!?" as a valid sequence for 3 zeros.
    while (*text != '\0')
    {
        const char *cp = memchr(BASE64_ALPHA, *text++, 65);
        unsigned char ch;

        if (cp == NULL)
            return -1;
        ch = (unsigned char)(cp - BASE64_ALPHA);
        if (ch > 0x3F)
            break;
        prefix = (prefix << 6)|(ch & 0x3F);
        if ((bits += 6) >= 8)
        {
            if (bufsize <= rlen)
                return -1;
            *rptr++ = (prefix >> (bits - 8)) & 0xFF;
            rlen++;
            bits -= 8;
        }
    }
    if ((prefix & ((1u << bits) - 1)) != 0)
        return -1; // Padding bits are not zero
    return rlen;
}

/**
 * @file
 * Common authentication functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include "auth.h"
#include "authfile.h"
#include "authmethod.h"
#include "socks5bits.h"

/**
 * List of supported methods, in preference decreasing order
 */
static const auth_method_t AUTH_METHODS[] = {
#if HAVE_CRYPTO_HMACMD5
    { SOCKS_AUTH_CHAP,    "chap",  auth_method_chap  },
#endif // HAVE_CRYPTO_HMACMD5
    { SOCKS_AUTH_BASIC,   "basic", auth_method_basic },
    { SOCKS_AUTH_NONE,    NULL,    NULL },
    { SOCKS_AUTH_INVALID, NULL,    NULL }
};

/**
 * Find a suitable method from client-provided offer
 *
 * @param offer    array of offered authentication methods.
 * @param offerlen length of array of authentication methods.
 * @return descriptor of selected authentication method, or NULL if no match.
 */
const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen)
{
    const auth_method_t *m;

    for (m = AUTH_METHODS; m->method != SOCKS_AUTH_INVALID; m++)
    {
        if (m->method == SOCKS_AUTH_NONE && !authfile_anonymous(-1))
            continue;
        if (m->callback != NULL && m->callback(NULL, -1, NULL) != 0)
            continue;
        if (memchr(offer, m->method, offerlen) != NULL)
            return m;
    }
    return NULL;
}

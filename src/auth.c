#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include "auth.h"
#include "authuser.h"
#include "authmethod.h"
#include "socks5bits.h"

/**
 * List of supported methods, in preference decreasing order
 */
static const auth_method_t AUTH_METHODS[] = {
    { SOCKS_AUTH_BASIC,   auth_method_basic },
    { SOCKS_AUTH_NONE,    NULL              },
    { SOCKS_AUTH_INVALID, NULL              }
};

/**
 * Get username from opaque user pointer
 */
const char *auth_get_username(const void *auth)
{
    return auth == NULL ? NULL : ((const authuser_t *)auth)->username;
}

/**
 * Find a suitable method from client-provided offer
 */
const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen)
{
    const auth_method_t *m;

    for (m = AUTH_METHODS; m->method != SOCKS_AUTH_INVALID; m++)
    {
        if (!authuser_method_allowed(m->method))
            continue;
        if (memchr(offer, m->method, offerlen) != NULL)
            return m;
    }
    return NULL;
}

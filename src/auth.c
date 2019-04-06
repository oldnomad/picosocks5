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
    { SOCKS_AUTH_CHAP,    "chap",
      .callback  = auth_method_chap,
      .generator = auth_secret_chap },
    { SOCKS_AUTH_BASIC,   "basic",
      .callback  = auth_method_basic,
      .generator = auth_secret_basic },
    { SOCKS_AUTH_NONE,    NULL, NULL, NULL },
    { SOCKS_AUTH_INVALID, NULL, NULL, NULL }
};

/**
 * Prefix for Base64 secret encoding
 */
const char   BASE64_PREFIX[]   = "$base64$";
const size_t BASE64_PREFIX_LEN = sizeof(BASE64_PREFIX) - 1;

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

/**
 * Find authentication method by its name
 */
const auth_method_t *auth_find_method(const char *name)
{
    const auth_method_t *m;

    if (name == NULL || *name == '\0')
        name = "basic";
    for (m = AUTH_METHODS; m->method != SOCKS_AUTH_INVALID; m++)
        if (m->name != NULL && strcmp(name, m->name) == 0)
            return m;
    return NULL;
}

/**
 * List all known methods.
 */
const auth_method_t *auth_all_methods(void)
{
    return AUTH_METHODS;
}

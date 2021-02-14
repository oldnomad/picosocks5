/**
 * @file
 * Common authentication functions.
 */
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
#if HAVE_CRYPTO_HMACMD5
    { SOCKS_AUTH_CHAP,    "chap",
      .callback  = auth_method_chap,
      .generator = auth_secret_chap },
#endif // HAVE_CRYPTO_HMACMD5
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
/**
 * Length of prefix for Base64 secret encoding
 */
const size_t BASE64_PREFIX_LEN = sizeof(BASE64_PREFIX) - 1;

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
        if (!authuser_method_allowed(m->method))
            continue;
        if (memchr(offer, m->method, offerlen) != NULL)
            return m;
    }
    return NULL;
}

/**
 * Find authentication method by its name
 *
 * @param name name of aithentication method.
 * @return descriptor of authentication method, or NULL if not found.
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
 *
 * @return array of known authentication method descriptors.
 */
const auth_method_t *auth_all_methods(void)
{
    return AUTH_METHODS;
}

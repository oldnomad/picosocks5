/**
 * @file
 * Crypto functions (GnuTLS).
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "crypto.h"
#include "logger.h"

void crypto_init(void)
{
    if (gnutls_global_init() != 0)
    {
        logger(LOG_ERR, "FATAL: Failed to initialize GnuTLS");
        exit(1);
    }
}

void crypto_generate_nonce(unsigned char *buffer, size_t buflen)
{
    int err = gnutls_rnd(GNUTLS_RND_NONCE, buffer, buflen);
    if (err != 0)
    {
        logger(LOG_ERR, "FATAL: Failed to get random data: %s", gnutls_strerror(err));
        exit(1);
    }
}

int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen)
{
    int err;

    if (reslen != CRYPTO_MD5_SIZE)
    {
        logger(LOG_ERR, "FATAL: Library MD5 hash length != %zu", reslen);
        exit(1);
    }
    err = gnutls_hmac_fast(GNUTLS_MAC_MD5, key, keylen, msg, msglen, res);
    if (err != 0)
    {
        logger(LOG_ERR, "HMAC-MD5 hash failed: %s", gnutls_strerror(err));
        return -1;
    }
    return 0;
}

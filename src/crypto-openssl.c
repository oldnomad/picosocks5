#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <syslog.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "crypto.h"
#include "logger.h"

static void openssl_error(int prio, const char *fmt, unsigned long err)
{
    char errbuf[256];

    ERR_error_string_n(err, errbuf, sizeof(errbuf));
    logger(prio, fmt, errbuf);
}

void crypto_init(void)
{
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS |
                            OPENSSL_INIT_NO_ADD_ALL_CIPHERS |
                            OPENSSL_INIT_NO_ADD_ALL_DIGESTS |
                            OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 0)
    {
        logger(LOG_ERR, "FATAL: Failed to initialize OpenSSL");
        exit(1);
    }
}

void crypto_generate_nonce(unsigned char *buffer, size_t buflen)
{
    if (RAND_bytes(buffer, buflen) == 0)
    {
        openssl_error(LOG_ERR, "FATAL: Failed to get random data: %s", ERR_get_error());
        exit(1);
    }
}

int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen)
{
    unsigned char *ukey = NULL, *ret;
    ssize_t ulen;
    unsigned int rlen = reslen;
    unsigned long err;

    if (reslen != CRYPTO_MD5_SIZE)
    {
        logger(LOG_ERR, "FATAL: Library MD5 hash length != %zu", reslen);
        exit(1);
    }
    ret = HMAC(EVP_md5(), key, keylen, msg, msglen, res, &rlen);
    err = ERR_get_error();
    if (ukey != NULL)
        OPENSSL_clear_free(ukey, ulen);
    if (ret == NULL)
    {
        openssl_error(LOG_ERR, "HMAC-MD5 hash failed: %s", err);
        return -1;
    }
    return 0;
}
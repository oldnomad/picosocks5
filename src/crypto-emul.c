/**
 * @file
 * Crypto functions (emulated).
 *
 * Implementation of MD5 in this file is based on classic public domain
 * code by Colin Plumb.
 */
#include <stdint.h>
#include <string.h>
#include "internal/md5.h"
#include "internal/prng.h"

void crypto_init(void)
{
    prng_init();
}

void crypto_generate_nonce(unsigned char *buffer, size_t buflen)
{
    prng_generate((void *)buffer, buflen);
}

#define CRYPTO_HMAC_BLKSIZE 64 ///< HMAC block size ("B").

int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen)
{
    /*
     * Code below follows RFC 2104 as close as possible.
     */
    struct MD5Context ctxt;
    unsigned char ipad[CRYPTO_HMAC_BLKSIZE];
    unsigned char opad[CRYPTO_HMAC_BLKSIZE];
    unsigned char keybuf[CRYPTO_MD5_SIZE];
    size_t i;

    if (reslen != CRYPTO_MD5_SIZE)
    {
        logger(LOG_ERR, "FATAL: MD5 hash length != %zu", reslen);
        exit(1);
    }
    if (keylen > CRYPTO_HMAC_BLKSIZE) {
        MD5Init(&ctxt);
        MD5Update(&ctxt, key, keylen);
        MD5Final(keybuf, &ctxt);
        key = keybuf;
        keylen = CRYPTO_MD5_SIZE;
    }
    memset(ipad, 0, CRYPTO_HMAC_BLKSIZE);
    memcpy(ipad, key, keylen);
    memset(opad, 0, CRYPTO_HMAC_BLKSIZE);
    memcpy(opad, key, keylen);
    for (i = 0; i < CRYPTO_HMAC_BLKSIZE; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }
    MD5Init(&ctxt);
    MD5Update(&ctxt, ipad, CRYPTO_HMAC_BLKSIZE);
    MD5Update(&ctxt, msg, msglen);
    MD5Final(res, &ctxt);

    MD5Init(&ctxt);
    MD5Update(&ctxt, opad, CRYPTO_HMAC_BLKSIZE);
    MD5Update(&ctxt, res, CRYPTO_MD5_SIZE);
    MD5Final(res, &ctxt);
    return 0;
}

#include "internal/md5.c"
#include "internal/prng.c"

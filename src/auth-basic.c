/**
 * @file
 * Basic (RFC 1929) authentication method functions
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <crypt.h>
#include "logger.h"
#include "auth.h"
#include "authuser.h"
#include "authmethod.h"
#include "socks5bits.h"
#include "crypto.h"

#define DEFAULT_SALT_SIZE 8 ///< Number of salt characters to generate
static const char DEFAULT_SALT_PREFIX[] = "$6$"; ///< Default crypt(3) method

/**
 * AUTH METHOD: User/password authentication (RFC 1929)
 * @copydetails auth_callback_t
 */
int auth_method_basic(const char *logprefix, int stage, auth_context_t *ctxt)
{
    const char *user, *pass, *cpass;
    size_t ulen, plen;
    const struct auth_user *u;
    struct crypt_data cdata;
    char copy[256 + 256];

    if (stage != 0)
    {
        logger(LOG_WARNING, "<%s> Too many stages for basic auth", logprefix);
        return -1;
    }
    if (ctxt->challenge_length < 3 || ctxt->challenge[0] != 0x01 ||
        (ctxt->challenge[1] + 3u) > ctxt->challenge_length)
    {
MALFORMED:
        logger(LOG_WARNING, "<%s> Malformed basic auth packet", logprefix);
        return -1;
    }
    ulen = ctxt->challenge[1];
    plen = ctxt->challenge[2 + ulen];
    if ((ulen + plen + 3) > ctxt->challenge_length)
        goto MALFORMED;
    memcpy(copy, &ctxt->challenge[2], ulen + plen + 1);
    copy[ulen] = '\0';
    copy[ulen + 1 + plen] = '\0';
    user = copy;
    pass = &user[ulen + 1];

    u = NULL;
    while ((u = authuser_find(SOCKS_AUTH_BASIC, user, u)) != NULL)
    {
        cpass = crypt_r(pass, u->secret, &cdata);
        if (cpass != NULL && strcmp(cpass, u->secret) == 0)
            break;
    }
    if (u != NULL)
        ctxt->username = u->username;

    if (ctxt->response_maxlen < 2)
    {
        logger(LOG_WARNING, "<%s> Not enough space for basic auth response", logprefix);
        return -1;
    }
    ctxt->response[0] = 0x01;
    ctxt->response[1] = u == NULL ? 0x01 : 0x00;
    ctxt->response_length = 2;
    return u == NULL ? -1 : 0;
}

/**
 * AUTH GENERATOR: Encrypt a password
 * @copydetails auth_generator_t
 */
ssize_t auth_secret_basic(const char *secret, char *buffer, size_t bufsize)
{
    // Salt alphabet contains 64 symbols, 6 bits per character;
    // 4 characters contain 3 bytes (24 bits) of randomness
    static const char ALPHABET[] = "ABCDEFGHIJKLMNOP"
                                   "QRSTUVWXYZabcdef"
                                   "ghijklmnopqrstuv"
                                   "wxyz0123456789/.";
    struct crypt_data cdata;
    char salt[sizeof(DEFAULT_SALT_PREFIX) + DEFAULT_SALT_SIZE + 1], *ep;
    const char *cpass;
    unsigned char randval[(DEFAULT_SALT_SIZE*3 + 2)/4];
    unsigned rval = 0;
    size_t csize;
    int i, j;

    memcpy(salt, DEFAULT_SALT_PREFIX, sizeof(DEFAULT_SALT_PREFIX) - 1);
    ep = &salt[sizeof(DEFAULT_SALT_PREFIX) - 1];
    crypto_generate_nonce(randval, sizeof(randval));
    rval = 0;
    for (i = 0, j = 0; i < DEFAULT_SALT_SIZE; i++)
    {
        switch (i % 4)
        {
        case 0:
            rval = randval[j++];
            break;
        case 1:
            rval = rval|(((unsigned)randval[j++]) << 2);
            break;
        case 2:
            rval = rval|(((unsigned)randval[j++]) << 4);
            break;
        case 3:
            break;
        }
        *ep++ = ALPHABET[rval & 0x3F];
        rval >>= 6;
    }
    *ep++ = '$';
    *ep = '\0';
    cpass = crypt_r(secret, salt, &cdata);
    if (cpass == NULL)
    {
        logger(LOG_ERR, "Encryption error: %m");
        return -1;
    }
    csize = strlen(cpass);
    if (bufsize < csize)
    {
        logger(LOG_ERR, "Encrypted password is too long");
        return -1;
    }
    memcpy(buffer, cpass, csize);
    return csize;
}


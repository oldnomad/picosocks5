#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "logger.h"
#include "auth.h"
#include "authuser.h"
#include "authmethod.h"
#include "authfile.h"
#include "socks5bits.h"
#include "crypto.h"
#include "util.h"

#define CHALLENGE_LENGTH 128 // Challenge bytes

enum chap_state {
    CHAP_ALGO = 0,     // Waiting for algorithms
    CHAP_GOT_ALGO,     // Got algorithms, send selected algorithm and challenge
    CHAP_CHALLENGE,    // Sent challenge, waiting for response
    CHAP_GOT_RESPONSE, // Got response, send client auth status
    CHAP_SERVER_AUTH,  // Sent client auth status with server response, waiting for server auth status
    CHAP_DONE          // Authentication finished successfully
};

struct chap_data {
    enum chap_state   state; // Currentt authentication state
    const authuser_t *user;  // User to authenticate
    unsigned char     challenge[CHALLENGE_LENGTH]; // Challenge sent to client
};

#if HAVE_CRYPTO_HMACMD5
static const authuser_t *chap_find_user(const char *logprefix, const unsigned char *user, size_t ulen)
{
    // NOTE: ulen is guaranteed to be at most 255
    char uname[256];
    const authuser_t *u;

    memcpy(uname, user, ulen);
    uname[ulen] = '\0';
    u = authuser_find(SOCKS_AUTH_CHAP, uname, NULL);
    if (u == NULL)
        logger(LOG_WARNING, "<%s> CHAP user ID '%s' not found", logprefix, uname);
    return u;
}

static void chap_error(auth_context_t *ctxt, int prio, const char *msg, ...)
{
    if (msg != NULL)
    {
        va_list args;

        va_start(args, msg);
        logger_vararg(prio, msg, args);
        va_end(args);
    }
    if (ctxt->response_maxlen < 5)
        logger(LOG_ERR, "Buffer too small for error response");
    else
    {
        ctxt->response[0] = 0x01;
        ctxt->response[1] = 1;
        ctxt->response[2] = SOCKS_CHAP_ATTR_STATUS;
        ctxt->response[3] = 1;
        ctxt->response[4] = 255;
        ctxt->response_length = 5;
    }
}

/**
 * AUTH METHOD: CHAP (draft-ietf-aft-socks-chap-01.txt)
 */
int auth_method_chap(const char *logprefix, int stage, auth_context_t *ctxt)
{
    struct chap_data *chap;
    const unsigned char *dptr, *cresp = NULL, *cchal = NULL;
    size_t dlen, nattr, navas, alen, cresp_len = 0, cchal_len = 0;
    unsigned char attr, hash[CRYPTO_MD5_SIZE];
    const authuser_t *u;

    if (stage == 0)
    {
        if ((chap = malloc(sizeof(*chap))) == NULL)
        {
            logger(LOG_ERR, "<%s> Not enough memory for CHAP", logprefix);
            return -1;
        }
        chap->state = CHAP_ALGO;
        chap->user  = NULL;
        ctxt->authdata = chap;
    }
    else
    {
        chap = ctxt->authdata;
        if (chap == NULL)
        {
            logger(LOG_ERR, "<%s> CHAP context lost on stage %d", logprefix, stage);
            return -1;
        }
    }
    if (ctxt->challenge_length < 2 || ctxt->challenge[0] != 0x01)
    {
ON_MALFORMED:
        logger(LOG_WARNING, "<%s> Malformed CHAP auth packet", logprefix);
        return -1;
    }
    navas = ctxt->challenge[1];
    dptr  = &ctxt->challenge[2];
    dlen  = ctxt->challenge_length - 2;
    for (nattr = 0; nattr < navas; nattr++)
    {
        if (dlen < 2)
            goto ON_MALFORMED;
        attr = *dptr++;
        alen = *dptr++;
        dlen -= 2;
        if (dlen < alen)
            goto ON_MALFORMED;
        switch (attr)
        {
        case SOCKS_CHAP_ATTR_ALGO:
            if (chap->state != CHAP_ALGO)
            {
                chap_error(ctxt, LOG_WARNING, "<%s> CHAP algorithm offer out-of-order", logprefix);
                return -1;
            }
            // We support only HMAC-MD5
            if (memchr(dptr, SOCKS_CHAP_ALGO_HMAC_MD5, alen) == NULL)
            {
                chap_error(ctxt, LOG_DEBUG, "<%s> CHAP algorithm negotiation failed", logprefix);
                return -1;
            }
            chap->state = CHAP_GOT_ALGO;
            break;
        case SOCKS_CHAP_ATTR_USERID:
            u = chap_find_user(logprefix, dptr, alen);
            if (u == NULL)
            {
                chap_error(ctxt, 0, NULL);
                return -1;
            }
            if (chap->user != NULL)
            {
                if (chap->user != u)
                {
                    chap_error(ctxt, LOG_WARNING, "<%s> CHAP user renegotiation attempt", logprefix);
                    return -1;
                }
                break;
            }
            chap->user = u;
            break;
        case SOCKS_CHAP_ATTR_RESPONSE:
            if (chap->state != CHAP_CHALLENGE)
            {
                chap_error(ctxt, LOG_WARNING, "<%s> CHAP response out-of-order", logprefix);
                return -1;
            }
            cresp = dptr;
            cresp_len = alen;
            chap->state = CHAP_GOT_RESPONSE;
            break;
        case SOCKS_CHAP_ATTR_CHALLENGE:
            if (chap->state != CHAP_CHALLENGE && chap->state != CHAP_GOT_RESPONSE)
            {
                chap_error(ctxt, LOG_WARNING, "<%s> CHAP client challenge out-of-order", logprefix);
                return -1;
            }
            cchal = dptr;
            cchal_len = alen;
            break;
        case SOCKS_CHAP_ATTR_STATUS:
            if (chap->state != CHAP_SERVER_AUTH)
            {
                chap_error(ctxt, LOG_WARNING, "<%s> CHAP status out-of-order", logprefix);
                return -1;
            }
            if (alen == 0)
                goto BAD_STATUS;
            for (; alen > 0 && *dptr == '\0'; alen--, dptr++);
            if (alen != 0)
            {
BAD_STATUS:
                chap_error(ctxt, LOG_WARNING, "<%s> CHAP client refused to authenticate us", logprefix);
                return -1;
            }
            chap->state = CHAP_DONE;
            break;
        }
        dptr += alen;
        dlen -= alen;
    }
    if (cchal != NULL && chap->state != CHAP_GOT_RESPONSE)
    {
        chap_error(ctxt, LOG_WARNING, "<%s> CHAP client challenge out-of-order", logprefix);
        return -1;
    }
    switch (chap->state)
    {
    case CHAP_ALGO: // Still waiting for algorithms offer
    case CHAP_CHALLENGE: // Still waiting for client response
    case CHAP_SERVER_AUTH: // Still waiting for server auth status
        break;
    case CHAP_GOT_ALGO: // Got algorithms, send selected algorithm
        // Length: 2 (prefix) + 3 (algo attr) + 2 (chal attr) + CHALLENGE_LENGTH
        if (ctxt->response_maxlen < (7 + CHALLENGE_LENGTH))
        {
            chap_error(ctxt, LOG_WARNING, "<%s> Buffer too small for CHAP", logprefix);
            return -1;
        }
        ctxt->response[0] = 0x01;
        ctxt->response[1] = 0x02;
        ctxt->response[2] = SOCKS_CHAP_ATTR_ALGO;
        ctxt->response[3] = 1;
        ctxt->response[4] = SOCKS_CHAP_ALGO_HMAC_MD5;
        ctxt->response[5] = SOCKS_CHAP_ATTR_CHALLENGE;
        ctxt->response[6] = CHALLENGE_LENGTH;
        crypto_generate_nonce(chap->challenge, sizeof(chap->challenge));
        memcpy(&ctxt->response[7], chap->challenge, sizeof(chap->challenge));
        ctxt->response_length = 7 + sizeof(chap->challenge);
        chap->state = CHAP_CHALLENGE;
        break;
    case CHAP_GOT_RESPONSE: // Got response, send client auth status
        if (chap->user == NULL)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP response without user ID", logprefix);
            return -1;
        }
        if (crypto_hmac_md5(chap->user->secret, chap->user->secretlen,
                            chap->challenge, sizeof(chap->challenge),
                            hash, CRYPTO_MD5_SIZE) != 0)
        {
            chap_error(ctxt, 0, NULL);
            return -1;
        }
        if (cresp_len != CRYPTO_MD5_SIZE || memcmp(cresp, hash, CRYPTO_MD5_SIZE) != 0)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP response doesn't match", logprefix);
            return -1;
        }
        // Length: 2 (prefix) + 3 (status attr); optionally add 2 (resp attr) + hash size
        if (ctxt->response_maxlen < (7 + CRYPTO_MD5_SIZE))
        {
            chap_error(ctxt, LOG_WARNING, "<%s> Buffer too small for CHAP", logprefix);
            return -1;
        }
        ctxt->response[0] = 0x01;
        ctxt->response[1] = 0x01;
        ctxt->response[2] = SOCKS_CHAP_ATTR_STATUS;
        ctxt->response[3] = 1;
        ctxt->response[4] = 0;
        ctxt->response_length = 5;
        if (cchal == NULL)
            return 0;
        u = authuser_find_server(SOCKS_AUTH_CHAP);
        if (u == NULL)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP client wants auth, but we don't have it", logprefix);
            return -1;
        }
        if (crypto_hmac_md5(u->secret, u->secretlen,
                            cchal, cchal_len,
                            hash, CRYPTO_MD5_SIZE) != 0)
        {
            chap_error(ctxt, 0, NULL);
            return -1;
        }
        ctxt->response[1]++;
        ctxt->response[5] = SOCKS_CHAP_ATTR_RESPONSE;
        ctxt->response[6] = CRYPTO_MD5_SIZE;
        memcpy(&ctxt->response[7], hash, CRYPTO_MD5_SIZE);
        ctxt->response_length += 2 + CRYPTO_MD5_SIZE;
        chap->state = CHAP_SERVER_AUTH;
        break;
    case CHAP_DONE: // Done
        return 0;
    }
    return 1;
}
#else // !HAVE_CRYPTO_HMACMD5
/**
 * DISABLED AUTH METHOD: CHAP (draft-ietf-aft-socks-chap-01.txt)
 */
int auth_method_chap(const char *logprefix, int stage, auth_context_t *ctxt)
{
    (void)logprefix;
    (void)stage;
    (void)ctxt;
    return -1;
}
#endif // HAVE_CRYPTO_HMACMD5

/**
 * AUTH GENERATOR: Encode a password
 */
ssize_t auth_secret_chap(const char *password, char *buffer, size_t bufsize)
{
    ssize_t seclen;

    if (bufsize <= BASE64_PREFIX_LEN)
        goto TOO_LONG;
    memcpy(buffer, BASE64_PREFIX, BASE64_PREFIX_LEN);
    buffer  += BASE64_PREFIX_LEN;
    bufsize -= BASE64_PREFIX_LEN;
    if ((seclen = util_base64_encode(password, strlen(password), buffer, bufsize)) < 0)
    {
TOO_LONG:
        logger(LOG_ERR, "Encoded password is too long");
        return -1;
    }
    return seclen + BASE64_PREFIX_LEN;
}

/**
 * @file
 * Common authentication functions.
 *
 * NOTES ON AUTH METHODS
 *
 * - Each method consists of sub-negotiation stages, numbered from zero.
 * - On each stage:
 *   - Client sends a challenge.
 *   - Framework calls the method-specific function.
 *     - If the function returns a negative value, authentication fails.
 *     - If the function returns a zero, authentication succeeds.
 *     - If the function returns a positive value, authentication continues.
 *     - Regardless of the function return value, if field response_length
 *       is non-zero, response is sent to client.
 *   - If authentication succeeds and field auth is non-null, it contains
 *     an opaque pointer to auth_user.
 *
 * As a sepcial case, when given stage number -1, callback returns success
 * if this authentication method is available.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "logger.h"
#include "auth.h"
#include "authfile.h"
#include "socks5bits.h"
#include "crypto.h"

#define CHAP_CHALLENGE_LENGTH 128 ///< CHAP challenge size in bytes

static int auth_method_basic(const char *logprefix, int stage, auth_context_t *ctxt);
static int auth_method_chap(const char *logprefix, int stage, auth_context_t *ctxt);

/**
 * List of supported methods, in preference decreasing order
 */
static const auth_method_t AUTH_METHODS[] = {
    { SOCKS_AUTH_CHAP,    "chap",  auth_method_chap  },
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

/**
 * Basic (RFC 1929) authentication method callback.
 * @copydetails auth_callback_t
 */
static int auth_method_basic(const char *logprefix, int stage, auth_context_t *ctxt)
{
    const unsigned char *pass;
    size_t ulen, plen;
    char user[256];
    const void *source;
    int auth_ok = 0;

    if (stage == -1)
        return authfile_supported(AUTHFILE_LOGIN) ? 0 : -1;
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
    memcpy(user, &ctxt->challenge[2], ulen);
    user[ulen] = '\0';
    pass = &ctxt->challenge[3 + ulen];

    if ((source = authfile_find_user(user)) != NULL &&
        authfile_callback(source, AUTHFILE_LOGIN, user, pass, plen, NULL, 0) >= 0)
    {
        if (ctxt->username != NULL)
            free(ctxt->username);
        if ((ctxt->username = strdup(user)) == NULL)
        {
            logger(LOG_WARNING, "<%s> Not enough memory for username", logprefix);
            return -1;
        }
        auth_ok = 1;
    }

    if (ctxt->response_maxlen < 2)
    {
        logger(LOG_WARNING, "<%s> Not enough space for basic auth response", logprefix);
        return -1;
    }
    ctxt->response[0] = 0x01;
    ctxt->response[1] = auth_ok ? 0x00 : 0x01;
    ctxt->response_length = 2;
    return auth_ok ? 0 : -1;
}

/**
 * Respond with CHAP error.
 *
 * @param ctxt authentication context.
 * @param prio log message priority.
 * @param msg  log message format.
 * @param ...  log message parameters.
 */
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
 * CHAP (draft-ietf-aft-socks-chap-01.txt) authentication method callback.
 * @copydetails auth_callback_t
 */
static int auth_method_chap(const char *logprefix, int stage, auth_context_t *ctxt)
{
    enum chap_state {
        CHAP_ALGO = 0,     // Waiting for algorithms
        CHAP_GOT_ALGO,     // Got algorithms, send selected algorithm and challenge
        CHAP_CHALLENGE,    // Sent challenge, waiting for response
        CHAP_GOT_RESPONSE, // Got response, send client auth status
        CHAP_SERVER_AUTH,  // Sent client auth status with server response, waiting for server auth status
        CHAP_DONE          // Authentication finished successfully
    };
    struct chap_data {
        enum chap_state   state;
        const void       *source;
        char              username[256];
        unsigned char     challenge[CHAP_CHALLENGE_LENGTH];
    } *chap;
    const unsigned char *dptr, *cresp = NULL, *cchal = NULL;
    size_t dlen, nattr, navas, alen, cresp_len = 0, cchal_len = 0;
    unsigned char attr;

    if (stage == -1)
        return authfile_supported(AUTHFILE_HMAC_MD5_RESPONSE) ? 0 : -1;
    if (stage == 0)
    {
        if ((chap = malloc(sizeof(*chap))) == NULL)
        {
            logger(LOG_ERR, "<%s> Not enough memory for CHAP", logprefix);
            return -1;
        }
        chap->state       = CHAP_ALGO;
        chap->source      = NULL;
        chap->username[0] = '\0';
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
            {
                // NOTE: ulen is guaranteed to be at most 255
                char uname[256];
                const void *handle;

                memcpy(uname, dptr, alen);
                uname[alen] = '\0';
                handle = authfile_find_user(uname);
                if (handle == NULL)
                {
                    logger(LOG_WARNING, "<%s> CHAP user ID '%s' not found", logprefix, uname);
                    chap_error(ctxt, 0, NULL);
                    return -1;
                }
                if (chap->source != NULL)
                {
                    if (strcmp(chap->username, uname) != 0)
                    {
                        chap_error(ctxt, LOG_WARNING, "<%s> CHAP user renegotiation attempt", logprefix);
                        return -1;
                    }
                    break;
                }
                chap->source = handle;
                memcpy(chap->username, uname, alen + 1);
            }
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
        if (authfile_callback(chap->source, AUTHFILE_HMAC_MD5_CHALLENGE, chap->username,
                              NULL, 0, chap->challenge, sizeof(chap->challenge)) < 0)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP challenge failed", logprefix);
            return -1;
        }
        // Length: 2 (prefix) + 3 (algo attr) + 2 (chal attr) + CHALLENGE_LENGTH
        if (ctxt->response_maxlen < (7 + CHAP_CHALLENGE_LENGTH))
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
        ctxt->response[6] = CHAP_CHALLENGE_LENGTH;
        memcpy(&ctxt->response[7], chap->challenge, sizeof(chap->challenge));
        ctxt->response_length = 7 + sizeof(chap->challenge);
        chap->state = CHAP_CHALLENGE;
        break;
    case CHAP_GOT_RESPONSE: // Got response, send client auth status
        if (chap->source == NULL)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP response without user ID", logprefix);
            return -1;
        }
        if (authfile_callback(chap->source, AUTHFILE_HMAC_MD5_RESPONSE, chap->username,
                              cresp, cresp_len, chap->challenge, sizeof(chap->challenge)) < 0)
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
        ctxt->response[1]++;
        ctxt->response[5] = SOCKS_CHAP_ATTR_RESPONSE;
        ctxt->response[6] = CRYPTO_MD5_SIZE;
        if (authfile_callback(chap->source, AUTHFILE_HMAC_MD5_SERVER, chap->username,
                              cchal, cchal_len, &ctxt->response[7], CRYPTO_MD5_SIZE) < 0)
        {
            chap_error(ctxt, LOG_WARNING, "<%s> CHAP client wants auth, but we don't have it", logprefix);
            return -1;
        }
        ctxt->response_length += 2 + CRYPTO_MD5_SIZE;
        chap->state = CHAP_SERVER_AUTH;
        break;
    case CHAP_DONE: // Done
        return 0;
    }
    return 1;
}

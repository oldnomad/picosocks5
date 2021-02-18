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
#include "logger.h"
#include "auth.h"
#include "authfile.h"
#include "authmethod.h"

/**
 * Basic authentication method callback.
 * @copydetails auth_callback_t
 */
int auth_method_basic(const char *logprefix, int stage, auth_context_t *ctxt)
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

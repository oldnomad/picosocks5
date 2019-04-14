#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <crypt.h>
#include "logger.h"
#include "auth.h"
#include "authuser.h"
#include "authmethod.h"
#include "socks5bits.h"

/**
 * AUTH METHOD: User/password authentication (RFC 1929)
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
    if (u == NULL)
        return -1;
    ctxt->username = u->username;

    if (ctxt->response_maxlen < 2)
    {
        logger(LOG_WARNING, "<%s> Not enough space for basic auth response", logprefix);
        return -1;
    }
    ctxt->response[0] = 0x01;
    ctxt->response[1] = u == NULL ? 0x01 : 0x00;
    ctxt->response_length = 2;
    return 0;
}

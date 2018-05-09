#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <crypt.h>
#include "logger.h"
#include "auth.h"
#include "socks5bits.h"

/*
 * NOTES ON AUTH METHODS
 *
 * - Each method consists of sub-negotiation stages.
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
 */

struct auth_user {
    struct auth_user *next;
    int method;
    const char *username;
    const char *secret;
    size_t secretlen;
};

struct authfile_format {
    const char *prefix;
    void (*parse)(const char *filespec);
};

static int auth_method_basic(const char *peername, int stage, auth_context_t *ctxt);

static const auth_method_t METHODS[] = {
    { SOCKS_AUTH_BASIC, auth_method_basic },
    { SOCKS_AUTH_NONE,  NULL              } // Look, ma, no comma!
};

static void authfile_format_password(const char *filespec);

static const struct authfile_format FILE_FORMATS[] = {
    { "password", authfile_format_password },
    { NULL,       authfile_format_password }
};

static struct auth_user *USER_LIST = NULL;
static int ANON_ALLOW = 1;

int auth_anon_allow(int newstate)
{
    int oldstate = ANON_ALLOW;
    if (newstate >= 0)
       ANON_ALLOW = newstate;
    return oldstate;
}

int auth_username_append(int method, const char *username, const char *secret, size_t secretlen)
{
    struct auth_user *u;
    char *uptr, *sptr;
    size_t ulen = strlen(username) + 1;

    if ((u = malloc(sizeof(*u) + ulen + secretlen)) == NULL)
        return -1;
    uptr = (char *)&u[1];
    sptr = &uptr[ulen];
    u->next = NULL;
    u->method = method;
    u->username = uptr;
    u->secret = sptr;
    memcpy(uptr, username, ulen);
    memcpy(sptr, secret, secretlen);
    if (USER_LIST == NULL)
        USER_LIST = u;
    else
    {
        struct auth_user *prev;
        for (prev = USER_LIST; prev->next != NULL; prev = prev->next);
        prev->next = u;
    }
    return 0;
}

const char *auth_get_username(const void *auth)
{
    return auth == NULL ? NULL : ((const struct auth_user *)auth)->username;
}

void authfile_parse(const char *filespec)
{
    const struct authfile_format *format;
    size_t fslen = strlen(filespec);
    const char *fs = filespec;

    for (format = FILE_FORMATS; format->prefix != NULL; format++)
    {
        size_t plen = strlen(format->prefix);
        if (plen < fslen && filespec[plen] == ':' &&
            memcmp(format->prefix, filespec, plen) == 0)
        {
            fs = &filespec[plen + 1];
            break;
        }
    }
    format->parse(fs);
}

const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen)
{
    size_t i;

    for (i = 0; i < sizeof(METHODS)/sizeof(METHODS[0]); i++)
    {
        int method = METHODS[i].method;
        if (method == SOCKS_AUTH_NONE && ANON_ALLOW == 0)
            continue;
        // NOTE: Currently we allow _all_ non-anonymous methods iff there
        //       are _any_ users. That's not quite right.
        if (method != SOCKS_AUTH_NONE && USER_LIST == NULL)
            continue;
        if (memchr(offer, method, offerlen) != NULL)
            return &METHODS[i];
    }
    return NULL;
}

/*************************************
 * METHOD STAGE FUNCTIONS START HERE *
 *************************************/

static int auth_method_basic(const char *peername, int stage, auth_context_t *ctxt)
{
    const char *user, *pass, *cpass;
    size_t ulen, plen;
    const struct auth_user *u;
    struct crypt_data cdata;
    char copy[256 + 256];

    if (stage != 0)
    {
        logger(LOG_WARNING, "<%s> Too many stages for basic auth",
            peername);
        return -1;
    }
    if (ctxt->challenge_length < 3 || ctxt->challenge[0] != 0x01 ||
        (ctxt->challenge[1] + 3u) > ctxt->challenge_length)
    {
MALFORMED:
        logger(LOG_WARNING, "<%s> Malformed basic auth packet",
            peername);
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

    for (u = USER_LIST; u != NULL; u = u->next)
    {
        if (u->method != SOCKS_AUTH_BASIC ||
            strcmp(u->username, user) != 0)
            continue;
        cpass = crypt_r(pass, u->secret, &cdata);
        if (cpass != NULL && strcmp(cpass, u->secret) == 0)
            break;
    }
    ctxt->auth = u;

    if (ctxt->response_maxlen < 2)
    {
        logger(LOG_WARNING, "<%s> Not enough space for basic auth response",
            peername);
        return -1;
    }
    ctxt->response[0] = 0x01;
    ctxt->response[1] = u == NULL ? 0x01 : 0x00;
    ctxt->response_length = 2;
    return 0;
}


/************************************
 * FILE FORMAT FUNCTIONS START HERE *
 ************************************/

static void authfile_format_password(const char *filespec)
{
    FILE *f = fopen(filespec, "rt");
    char line[1024];

    if (f == NULL)
    {
        fprintf(stderr, "Cannot open auth file '%s': %m\n", filespec);
        exit(1);
    }
    while (fgets(line, sizeof(line), f) != NULL)
    {
        char *sp;
        for (sp = &line[strlen(line)];
             sp > line && (sp[-1] == '\n' || sp[-1] == '\r'); sp--);
        *sp = '\0';
        if ((sp = strchr(line, ':')) == NULL)
        {
            fprintf(stderr, "Unseparated line '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
        *sp++ = '\0';
        if (auth_username_append(SOCKS_AUTH_BASIC, line, sp, strlen(sp) + 1) != 0)
        {
            fprintf(stderr, "Failed to add username '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
    }
    fclose(f);
}

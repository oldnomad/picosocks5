#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "authuser.h"
#include "socks5bits.h"

static authuser_t *USER_LIST = NULL; // Linked list of users
static int ANON_ALLOW = 1; // Allow anonymous method (SOCKS_AUTH_NONE)

/**
 * Add new user
 */
int authuser_append(int method, const char *username, const char *secret, size_t secretlen)
{
    authuser_t *u;
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
        authuser_t *prev;
        for (prev = USER_LIST; prev->next != NULL; prev = prev->next);
        prev->next = u;
    }
    return 0;
}

/**
 * Get current anonymous access state and, optionally, modify it
 */
int authuser_anon_allow(int newstate)
{
    int oldstate = ANON_ALLOW;
    if (newstate >= 0)
       ANON_ALLOW = newstate;
    return oldstate;
}

/**
 * Check whether method is allowed
 */
int authuser_method_allowed(int method)
{
    authuser_t *u;

    if (method == SOCKS_AUTH_NONE)
        return ANON_ALLOW;
    for (u = USER_LIST; u != NULL; u = u->next)
        if (u->method == method)
            return 1;
    return 0;
}

/**
 * Find a user with specified method
 */
const authuser_t *authuser_find(int method, const char *username, const authuser_t *cur)
{
    const authuser_t *u = cur == NULL ? USER_LIST : cur->next;

    for (; u != NULL && (u->method != method ||
                         strcmp(u->username, username) != 0); u = u->next);
    return u;
}

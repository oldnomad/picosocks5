#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authuser.h"
#include "socks5bits.h"

struct authuser_container {
    struct authuser_container
              *next;
    authuser_t user;
    char       data[];
};

static struct authuser_container
          *USER_LIST = NULL; // Linked list of users
static int ANON_ALLOW = 0;   // Allow anonymous method, even if there are non-anon users

/**
 * Add new user
 */
int authuser_append(int method, const char *username, const char *secret, size_t secretlen)
{
    struct authuser_container *u;
    char *uptr, *sptr;
    size_t ulen = strlen(username) + 1;

    if ((u = malloc(sizeof(*u) + ulen + secretlen)) == NULL)
        return -1;
    uptr = u->data;
    sptr = &uptr[ulen];
    u->next = NULL;
    u->user.method   = method;
    u->user.username = uptr;
    u->user.secret   = sptr;
    memcpy(uptr, username, ulen);
    memcpy(sptr, secret, secretlen);
    if (USER_LIST == NULL)
        USER_LIST = u;
    else
    {
        struct authuser_container *prev;
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
    struct authuser_container *u;

    for (u = USER_LIST; u != NULL; u = u->next)
        if (u->user.method == method)
            return 1;
    if (method == SOCKS_AUTH_NONE && (USER_LIST == NULL || ANON_ALLOW))
        return 1;
    return 0;
}

/**
 * Find a user with specified method
 */
const authuser_t *authuser_find(int method, const char *username, const authuser_t *cur)
{
    const struct authuser_container *u;

    if (cur == NULL)
        u = USER_LIST;
    else
    {
        u = (const struct authuser_container *)
                ((const char *)cur - offsetof(struct authuser_container, user));
        u = u->next;
    }
    for (; u != NULL && (u->user.method != method ||
                         strcmp(u->user.username, username) != 0); u = u->next);
    return &u->user;
}

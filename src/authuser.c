/**
 * @file
 * User/secret functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authuser.h"
#include "socks5bits.h"

/**
 * List item for user/secret pair.
 */
struct authuser_container {
    struct authuser_container
              *next;    ///< Pointer to the next item.
    authuser_t user;    ///< User/secret descriptor.
    char       data[];  ///< Constants referred to from the descriptor.
};

static struct authuser_container
          *USER_LIST = NULL; ///< Linked list of user/secret pairs
static int ANON_ALLOW = 0;   ///< Flag to allow anonymous method, even if there are non-anon users

/**
 * Add new user
 *
 * @param method    authentication method code.
 * @param username  user name.
 * @param secret    secret bytes.
 * @param secretlen secret bytes length.
 * @return zero on success, or -1 on error.
 */
int authuser_append(int method, const char *username, const char *secret, size_t secretlen)
{
    struct authuser_container *u;
    char *uptr, *sptr;
    size_t ulen = username == NULL ? 0 : (strlen(username) + 1);

    if ((u = malloc(sizeof(*u) + ulen + secretlen)) == NULL)
        return -1;
    uptr = u->data;
    sptr = &uptr[ulen];
    u->next = NULL;
    u->user.method    = method;
    u->user.username  = username == NULL ? NULL : uptr;
    u->user.secret    = sptr;
    u->user.secretlen = secretlen;
    if (username != NULL)
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
 * Get current anonymous access flag and, optionally, modify it
 *
 * @param newstate new anonymous access flag, or -1 to avoid setting.
 * @return old anonymous access flag.
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
 *
 * @param method authentication method code.
 * @return true if method is allowed.
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
 *
 * @param method   authentication method code.
 * @param username user name.
 * @param cur      if not NULL, continue search after this element.
 * @return user/secret pair.
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
    for (; u != NULL &&
           (u->user.method != method ||
            u->user.username == NULL ||
            strcmp(u->user.username, username) != 0); u = u->next);
    return u == NULL ? NULL : &u->user;
}

/**
 * Find server-side authenticator with specified method
 *
 * @param method   authentication method code.
 * @return user/secret method for server-side authentication.
 */
const authuser_t *authuser_find_server(int method)
{
    const struct authuser_container *u;

    for (u = USER_LIST; u != NULL &&
                        (u->user.method != method || u->user.username != NULL); u = u->next);
    return u == NULL ? NULL : &u->user;
}

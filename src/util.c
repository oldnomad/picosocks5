#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include "util.h"

uid_t util_parse_user(const char *user)
{
    unsigned long uid;
    char *ep = NULL;

    uid = strtoul(user, &ep, 0);
    if (ep == NULL || *ep != '\0')
    {
        struct passwd *u = getpwnam(user);
        if (u == NULL)
            return (uid_t)-1;
        return u->pw_uid;
    }
    return uid;
}

gid_t util_parse_group(const char *group)
{
    unsigned long gid;
    char *ep = NULL;

    gid = strtoul(group, &ep, 0);
    if (ep == NULL || *ep != '\0')
    {
        struct group *g = getgrnam(group);
        if (g == NULL)
            return (gid_t)-1;
        return g->gr_gid;
    }
    return gid;
}

int util_decode_addr(const struct sockaddr *addr, socklen_t addrlen,
                     char *buffer, size_t buflen)
{
    char host[INET6_ADDRSTRLEN + 1] = "???", serv[16] = "?";
    const char *fmt;

    getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
                NI_NUMERICHOST|NI_NUMERICSERV);
    switch (addr->sa_family)
    {
    case AF_INET:
        fmt = "%s:%s";
        break;
    default:
        fmt = "[%s]:%s";
        break;
    }
    return snprintf(buffer, buflen, fmt, host, serv);
}

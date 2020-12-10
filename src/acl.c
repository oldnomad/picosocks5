#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#include "acl.h"
#include "logger.h"
#include "util.h"

struct acl_network {
    struct acl_network *next;     // Pointer to next network
    int allow;                    // Allow/deny flag
    struct sockaddr_storage addr; // Network address
    unsigned bits;                // Bitmask width
};

struct acl_set {
    struct acl_network *client_networks[2];
};

static struct acl_set ACL_GLOBAL = {
    .client_networks = { NULL, NULL }
};


/**
 * Match an address against a network.
 */
static int match_network(const struct sockaddr *addr,
                         const struct sockaddr *netaddr, unsigned bits)
{
    if (addr->sa_family != netaddr->sa_family)
        return 0;
    switch (netaddr->sa_family)
    {
    case AF_INET:
        if (bits <= 32)
        {
            in_addr_t a = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
            in_addr_t n = ntohl(((const struct sockaddr_in *)netaddr)->sin_addr.s_addr);
            unsigned b = 32 - bits;
            return (a >> b) == (n >> b);
        }
        break;
    case AF_INET6:
        if (bits <= 128)
        {
            const struct in6_addr *a = &((const struct sockaddr_in6 *)addr)->sin6_addr;
            const struct in6_addr *n = &((const struct sockaddr_in6 *)netaddr)->sin6_addr;
            int oi;

            for (oi = 0; bits >= 8 && oi < 16; oi++, bits -= 8)
                if (a->s6_addr[oi] != n->s6_addr[oi])
                    return 0;
            if (bits == 0)
                return 1;
            if (oi < 16)
            {
                unsigned b = 8 - bits;
                return (a->s6_addr[oi] >> b) == (n->s6_addr[oi] >> b);
            }
        }
        break;
    }
    return 0;
}

/**
 * Check client address against an ACL set.
 */
static int check_client_address(const struct acl_set *set,
                                const struct sockaddr *addr,
                                const struct acl_network **pnet) {
    const struct acl_network *net;

    if (pnet != NULL)
        *pnet = NULL;
    if (set->client_networks[0] == NULL)
        return 1;
    for (net = set->client_networks[0]; net != NULL; net = net->next)
        if (match_network(addr, (const struct sockaddr *)&net->addr, net->bits)) {
            if (pnet != NULL)
                *pnet = net;
            return net->allow;
        }
    return 0;
}

/**
 * Check whether client address is allowed.
 */
int acl_check_client_address(const struct sockaddr *addr, size_t addrlen) {
    const struct acl_network *net = NULL;
    char hostaddr[UTIL_ADDRSTRLEN + 1];
    char netaddr[UTIL_ADDRSTRLEN + 8];

    if (check_client_address(&ACL_GLOBAL, addr, &net) != 0)
        return 1;
    util_decode_addr(addr, addrlen, hostaddr, sizeof(hostaddr));
    if (net != NULL)
        util_decode_network((const struct sockaddr *)&net->addr, sizeof(net->addr),
                            net->bits, netaddr, sizeof(netaddr));
    else
    {
        netaddr[0] = '*';
        netaddr[1] = '\0';
    }
    logger(LOG_WARNING, "Connection from disallowed address <%s> in network <%s>, dropped", hostaddr, netaddr);
    return 0;
}

/**
 * Add allowed or disallowed client network.
 */
int acl_add_client_network(const char *group, int allow, const char *address, unsigned bits)
{
    struct acl_set *set;
    struct acl_network *net;
    struct addrinfo *addrinfo;
    struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
    int ret;
    static const struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC,
    };

    (void)group;
    set = &ACL_GLOBAL; // TODO: Find group by name
    if ((ret = getaddrinfo(address, NULL, &hints, &addrinfo)) != 0)
    {
        logger(LOG_ERR, "Failed to resolve network address '%s': %s", address, gai_strerror(ret));
        return -1;
    }
    if (addrinfo != NULL)
    {
        if (addrinfo->ai_addrlen <= sizeof(addr))
        {
            memset(&addr, 0, sizeof(addr));
            memcpy(&addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
        }
        freeaddrinfo(addrinfo);
    }
    switch (addr.ss_family)
    {
    default:
        logger(LOG_ERR, "Unknown network address '%s'", address);
        return -1;
    case AF_INET:
        if (bits > 32)
            bits = 32;
        break;
    case AF_INET6:
        if (bits > 128)
            bits = 128;
        break;
    }
    if ((net = malloc(sizeof(*net))) == NULL)
    {
        logger(LOG_ERR, "Not enough memory for network ACLs");
        return -1;
    }
    net->next = NULL;
    net->allow = allow;
    net->addr = addr;
    net->bits = bits;
    if (set->client_networks[1] == NULL)
        set->client_networks[0] = net;
    else
        set->client_networks[1]->next = net;
    set->client_networks[1] = net;
    return 0;
}

/**
 * Report configuration parameters.
 */
void acl_show_config(void)
{
    char hostaddr[UTIL_ADDRSTRLEN + 8];
    const struct acl_network *net;

    for (net = ACL_GLOBAL.client_networks[0]; net != NULL; net = net->next)
    {
        util_decode_network((const struct sockaddr *)&net->addr, sizeof(net->addr), net->bits,
                            hostaddr, sizeof(hostaddr));
        logger(LOG_INFO, "%s network <%s>", net->allow ? "Allowed" : "Disallowed", hostaddr);
    }
}

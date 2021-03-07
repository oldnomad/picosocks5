/**
 * @file
 * ACL management functions.
 */
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
#include "socks5bits.h"
#include "util.h"

/**
 * Structure fot network list element.
 */
struct acl_network {
    struct acl_network *next;     ///< Pointer to next network
    int allow;                    ///< Allow/deny flag
    struct sockaddr_storage addr; ///< Network address
    unsigned bits;                ///< Bitmask width
};

/**
 * Structure for request rule list element.
 */
struct acl_request {
    struct acl_request *next;     ///< Pointer to next request rule
    int allow;                    ///< Allow/deny flag
    int type;                     ///< Request type
#define SOCKS_CMDS_ALL 0x8000     ///< Wildcard request type value
    struct sockaddr_storage addr; ///< Network address
    unsigned bits;                ///< Bitmask width
};

/**
 * Structure for named ACL set.
 */
struct acl_set {
    struct acl_set       *next;   ///< Pointer to next entry (in a list)
    const char           *name;   ///< ACL set name
    const struct acl_set *base;   ///< ACL set parent set

    struct acl_network *client_networks[2]; ///< List of networks
    struct acl_request *client_requests[2]; ///< List of request rules
};

/**
 * Global (root) ACL set.
 */
static struct acl_set ACL_GLOBAL = {
    .next = NULL,
    .name = "",
    .base = NULL,
    .client_networks = { NULL, NULL },
    .client_requests = { NULL, NULL },
};
/**
 * List of named ACL sets.
 */
static struct acl_set *ACL_NAMED_LIST[2] = { NULL, NULL };
/**
 * ACL set name for anonymous and groupless users.
 */
const char ACL_ANON_GROUP[] = "*";

/**
 * Known names for request types.
 */
static const struct {
    int         type;   ///< Request type value
    ssize_t     length; ///< Name length
    const char *name;   ///< Name
} REQUEST_TYPES[] = {
    { SOCKS_CMD_CONNECT,   7, "connect" },
    { SOCKS_CMD_BIND,      4, "bind"    },
    { SOCKS_CMD_ASSOCIATE, 5, "assoc"   },
    { SOCKS_CMDS_ALL,      3, "all"     },
    { -1,                  0, NULL      }
};


/**
 * Match an address against a network.
 *
 * @param addr    address to check.
 * @param netaddr network address.
 * @param bits    network bitmask width.
 * @return true if address is in the network.
 */
static int match_network(const struct sockaddr *addr,
                         const struct sockaddr *netaddr, unsigned bits)
{
    if (bits == 0)
        return 1;
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
 *
 * @param set  ACL set to check against.
 * @param addr address to check.
 * @param pnet if not NULL, buffer for network that matched.
 * @return true if address is allowed.
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
    if (set->base != NULL)
        return check_client_address(set->base, addr, pnet);
    return 0;
}

/**
 * Check request against an ACL set.
 *
 * @param set  ACL set to check against.
 * @param type request type.
 * @param addr destination address.
 * @param preq if not NULL, buffer for request rule that matched.
 * @return true if request is allowed.
 */
static int check_request(const struct acl_set *set,
                         unsigned char type,
                         const struct sockaddr *addr,
                         const struct acl_request **preq) {
    const struct acl_request *req;

    if (preq != NULL)
        *preq = NULL;
    if (set->client_requests[0] == NULL)
        return 1;
    for (req = set->client_requests[0]; req != NULL; req = req->next)
        if ((req->type == SOCKS_CMDS_ALL || req->type == type) &&
            match_network(addr, (const struct sockaddr *)&req->addr, req->bits)) {
            if (preq != NULL)
                *preq = req;
            return req->allow;
        }
    if (set->base != NULL)
        return check_request(set->base, type, addr, preq);
    return 0;
}

/**
 * Convert network to address/bits.
 *
 * @param address network address as a text.
 * @param pbits   pointer to network bitmask width (will be clamped).
 * @param addr    buffer for network address.
 * @return zero on success, or -1 on error.
 */
static int normalize_network(const char *address, unsigned *pbits,
                             struct sockaddr_storage *addr) {
    int ret;
    struct addrinfo *addrinfo;
    static const struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC,
    };

    if (address == NULL || *pbits == 0)
    {
        *pbits = 0;
        return 0;
    }
    if ((ret = getaddrinfo(address, NULL, &hints, &addrinfo)) != 0)
    {
        logger(LOG_ERR, "Failed to resolve network address '%s': %s", address, gai_strerror(ret));
        return -1;
    }
    if (addrinfo != NULL)
    {
        if (addrinfo->ai_addrlen <= sizeof(*addr))
        {
            memset(addr, 0, sizeof(*addr));
            memcpy(addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
        }
        freeaddrinfo(addrinfo);
    }
    switch (addr->ss_family)
    {
    default:
        logger(LOG_ERR, "Unknown network address '%s'", address);
        return -1;
    case AF_INET:
        if (*pbits > 32)
            *pbits = 32;
        break;
    case AF_INET6:
        if (*pbits > 128)
            *pbits = 128;
        break;
    }
    return 0;
}

/**
 * Find group by name.
 *
 * @param group ACL set name.
 * @return ACL set, or NULL if not found.
 */
static const struct acl_set *find_acl_group(const char *group) {
    const struct acl_set *set;

    if (group == NULL)
        return &ACL_GLOBAL;
    for (set = ACL_NAMED_LIST[0]; set != NULL; set = set->next)
        if (set->name != NULL && strcmp(set->name, group) == 0)
            return set;
    return NULL;
}

/**
 * Find group by name, or create a new one.
 *
 * @param group ACL set name.
 * @return ACL set, or NULL on error.
 */
static struct acl_set *modify_acl_group(const char *group) {
    struct acl_set *set;
    size_t nlen;

    if (group == NULL)
        return &ACL_GLOBAL;
    for (set = ACL_NAMED_LIST[0]; set != NULL; set = set->next)
        if (set->name != NULL && strcmp(set->name, group) == 0)
            return set;
    nlen = strlen(group) + 1;
    if ((set = malloc(sizeof(*set) + nlen)) == NULL)
        return NULL;
    set->next = NULL;
    set->name = (char *)&set[1];
    memcpy(&set[1], group, nlen);
    set->base = &ACL_GLOBAL;
    set->client_networks[0] = NULL;
    set->client_networks[1] = NULL;
    set->client_requests[0] = NULL;
    set->client_requests[1] = NULL;
    if (ACL_NAMED_LIST[1] == NULL)
        ACL_NAMED_LIST[0] = set;
    else
        ACL_NAMED_LIST[1]->next = set;
    ACL_NAMED_LIST[1] = set;
    return set;
}

/**
 * Check whether client address is allowed.
 *
 * @param group   ACL set name.
 * @param addr    address to check.
 * @param addrlen size of address.
 * @return true if address is allowed.
 */
int acl_check_client_address(const char *group, const struct sockaddr *addr, size_t addrlen) {
    const struct acl_set *set;
    const struct acl_network *net = NULL;
    char hostaddr[UTIL_ADDRSTRLEN + 1];
    char netaddr[UTIL_ADDRSTRLEN + 8];

    if ((set = find_acl_group(group)) == NULL)
        set = &ACL_GLOBAL;
    if (check_client_address(set, addr, &net))
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
 *
 * @param group   ACL set name.
 * @param allow   whether the network will be allowed.
 * @param address network address as a text.
 * @param bits    network bitmask width.
 * @return zero on success, or -1 on error.
 */
int acl_add_client_network(const char *group, int allow, const char *address, unsigned bits)
{
    struct acl_set *set;
    struct acl_network *net;
    struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };

    if ((set = modify_acl_group(group)) == NULL)
    {
        logger(LOG_ERR, "Not enough memory for ACL group '%s'", group);
        return -1;
    }
    if (normalize_network(address, &bits, &addr) != 0)
        return -1;
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
 * Find SOCKS request type by name.
 *
 * @param name purported request type name.
 * @param len  length of the name, or -1 if NUL-terminated.
 * @return request type value, or -1 on error.
 */
int acl_find_request_type(const char *name, ssize_t len)
{
    size_t i;

    if (len < 0)
        len = strlen(name);
    for (i = 0; REQUEST_TYPES[i].name != NULL; i++)
        if (len == REQUEST_TYPES[i].length && memcmp(name, REQUEST_TYPES[i].name, len) == 0)
            return REQUEST_TYPES[i].type;
    return -1;
}

/**
 * Find SOCKS request type name by value.
 *
 * @param type request type value.
 * @return request type name, or NULL on error.
 */
const char *acl_get_request_type_name(int type)
{
    size_t i;

    for (i = 0; REQUEST_TYPES[i].name != NULL; i++)
        if (type == REQUEST_TYPES[i].type)
            return REQUEST_TYPES[i].name;
    return NULL;
}

/**
 * Check whether request is allowed.
 *
 * @param group   ACL set name.
 * @param type    request type.
 * @param addr    destination address.
 * @param addrlen destination address length.
 * @return true if request is allowed.
 */
int acl_check_request(const char *group, unsigned char type, const struct sockaddr *addr, size_t addrlen)
{
    const struct acl_set *set;
    const struct acl_request *req = NULL;
    char hostaddr[UTIL_ADDRSTRLEN + 1];
    char netaddr[UTIL_ADDRSTRLEN + 8];

    if ((set = find_acl_group(group)) == NULL)
        set = &ACL_GLOBAL;
    if (check_request(set, type, addr, &req))
        return 1;
    util_decode_addr(addr, addrlen, hostaddr, sizeof(hostaddr));
    if (req != NULL)
        util_decode_network((const struct sockaddr *)&req->addr, sizeof(req->addr),
                            req->bits, netaddr, sizeof(netaddr));
    else
    {
        netaddr[0] = '*';
        netaddr[1] = '\0';
    }
    logger(LOG_WARNING, "Disallowed request 0x%02X to address <%s> in network <%s>, dropped", type, hostaddr, netaddr);
    return 0;
}

/**
 * Add allowed or disallowed SOCKS requests.
 *
 * @param group   ACL set name.
 * @param allow   whether the rule will be allowed.
 * @param type    request type value.
 * @param address destination network address as a text.
 * @param bits    destination network bitmask width.
 * @return zero on success, or -1 on error.
 */
int acl_add_request_rule(const char *group, int allow, int type, const char *address, unsigned bits)
{
    struct acl_set *set;
    struct acl_request *req;
    struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };

    if ((set = modify_acl_group(group)) == NULL)
    {
        logger(LOG_ERR, "Not enough memory for ACL group '%s'", group);
        return -1;
    }
    if (normalize_network(address, &bits, &addr) != 0)
        return -1;
    if ((req = malloc(sizeof(*req))) == NULL)
    {
        logger(LOG_ERR, "Not enough memory for request ACLs");
        return -1;
    }
    req->next = NULL;
    req->allow = allow;
    req->type = type;
    req->addr = addr;
    req->bits = bits;
    if (set->client_requests[1] == NULL)
        set->client_requests[0] = req;
    else
        set->client_requests[1]->next = req;
    set->client_requests[1] = req;
    return 0;
}

/**
 * Set parent ACL set to specified ACL set.
 *
 * Parent ACL should be already defined.
 *
 * @param group  ACL set name.
 * @param parent parent ACL set name.
 * @return zero on success, or -1 on error.
 */
int acl_set_parent(const char *group, const char *parent)
{
    const struct acl_set *pset, *s;
    struct acl_set *set;

    if (group == NULL || parent == NULL)
    {
        logger(LOG_ERR, "Invalud ACL group name");
        return -1;
    }
    if ((pset = find_acl_group(parent)) == NULL)
    {
        logger(LOG_ERR, "Unknown parent ACL[%s]", parent);
        return -1;
    }
    if ((set = modify_acl_group(group)) == NULL)
    {
        logger(LOG_ERR, "Not enough memory for ACL group '%s'", group);
        return -1;
    }
    for (s = pset; s != NULL; s = s->base)
        if (s == set)
        {
            logger(LOG_ERR, "Loop detected: ACL[%s] <-> ACL[%s]", group, parent);
            return -1;
        }
    set->base = pset;
    return 0;
}

/**
 * Report ACL set rules.
 *
 * @param set ACL set name.
 */
static void show_acl_set(const struct acl_set *set)
{
    char hostaddr[UTIL_ADDRSTRLEN + 8];
    const struct acl_network *net;
    const struct acl_request *req;

    if (set->base != NULL)
        logger(LOG_INFO, "ACL[%s]: Based on ACL[%s]", set->name, set->base->name);
    for (net = set->client_networks[0]; net != NULL; net = net->next)
    {
        util_decode_network((const struct sockaddr *)&net->addr, sizeof(net->addr), net->bits,
                            hostaddr, sizeof(hostaddr));
        logger(LOG_INFO, "ACL[%s]: %s network <%s>", set->name,
               net->allow ? "Allowed" : "Disallowed", hostaddr);
    }
    for (req = set->client_requests[0]; req != NULL; req = req->next)
    {
        util_decode_network((const struct sockaddr *)&req->addr, sizeof(req->addr), req->bits,
                            hostaddr, sizeof(hostaddr));
        logger(LOG_INFO, "ACL[%s]: %s request '%s' to network <%s>", set->name,
               req->allow ? "Allowed" : "Disallowed",
               acl_get_request_type_name(req->type), hostaddr);
    }
}

/**
 * Report configuration parameters.
 */
void acl_show_config(void)
{
    const struct acl_set *set;

    show_acl_set(&ACL_GLOBAL);
    for (set = ACL_NAMED_LIST[0]; set != NULL; set = set->next)
        show_acl_set(set);
}

#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif // HAVE_IFADDRS_H
#include <pthread.h>
#include "socks5.h"
#include "auth.h"
#include "logger.h"
#include "util.h"
#include "socks5bits.h"

typedef struct {
    int socket;                     // Client socket

    const char *username;           // Authenticated user (if any)
    void *authdata;                 // Additional malloc'ed data (if any)

    struct sockaddr_storage local;  // Local address and port
    struct sockaddr_storage client; // Client address and port
    struct sockaddr_storage server; // Destination server address and port
    char logprefix[256];            // Prefix for log messages

    unsigned char buffer[4096];     // I/O buffer
} socks_state_t;

static struct sockaddr_storage BIND_ADDRESS_IP4 = { .ss_family = AF_UNSPEC };
static struct sockaddr_storage BIND_ADDRESS_IP6 = { .ss_family = AF_UNSPEC };

/**
 * Build prefix for SOCKS log messages
 */
static void socks_logger_prefix(socks_state_t *conn, const char *state)
{
    char *ep = conn->logprefix;
    size_t elen = sizeof(conn->logprefix), len;

    *ep = '\0';
    if (conn->client.ss_family != AF_UNSPEC)
    {
        if (elen < (UTIL_ADDRSTRLEN + 1))
            return;
        util_decode_addr((struct sockaddr *)&conn->client, sizeof(conn->client),
                         ep, elen);
        len = strlen(ep);
        ep   += len;
        *ep++ = '|';
        *ep   = '\0';
        elen -= len + 1;
    }
    if (conn->server.ss_family != AF_UNSPEC)
    {
        if (elen < (UTIL_ADDRSTRLEN + 1))
            return;
        util_decode_addr((struct sockaddr *)&conn->server, sizeof(conn->server),
                         ep, elen);
        len = strlen(ep);
        ep   += len;
        *ep++ = '|';
        *ep   = '\0';
        elen -= len + 1;
    }
    len = strlen(state);
    if (elen <= len)
        return;
    strcpy(ep, state);
}

/**
 * Read from SOCKS control channel
 */
static ssize_t socks_read(const socks_state_t *conn, unsigned char *buffer, size_t bufsize)
{
    ssize_t len;

    if ((len = recv(conn->socket, buffer, bufsize, 0)) <= 0)
    {
        if (len < 0)
            logger(LOG_WARNING, "<%s> Error receiving data from client: %m", conn->logprefix);
        return -1;
    }
    return len;
}

/**
 * Write to SOCKS control channel
 */
static int socks_write(const socks_state_t *conn, const unsigned char *data, size_t length)
{
    if (send(conn->socket, data, length, 0) == -1)
    {
        logger(LOG_WARNING, "<%s> Error sending data to client: %m", conn->logprefix);
        return -1;
    }
    return 0;
}

/**
 * Negotiate authentication method and perform corresponding
 * sub-negotiation stages
 */
static int socks_negotiate_method(socks_state_t *conn)
{
    ssize_t len;
    int ret, stage;
    const auth_method_t *method;
    auth_context_t ctxt;

    socks_logger_prefix(conn, "OFFER");
    if ((len = socks_read(conn, conn->buffer, sizeof(conn->buffer))) < 0)
        return -1;
    if (len < 3 || conn->buffer[0] != SOCKS_VERSION5 ||
        conn->buffer[1] == 0 || (conn->buffer[1] + 2) > len)
    {
        logger(LOG_WARNING, "<%s> Malformed initial offer", conn->logprefix);
        return -1;
    }
    method = auth_negotiate_method(&conn->buffer[2], conn->buffer[1]);
    conn->buffer[0] = SOCKS_VERSION5;
    conn->buffer[1] = method == NULL ? SOCKS_AUTH_INVALID : method->method;
    if (socks_write(conn, conn->buffer, 2) < 0)
        return -1;
    if (method == NULL)
    {
        logger(LOG_NOTICE, "<%s> No authentication method available", conn->logprefix);
        return -1;
    }
    logger(LOG_DEBUG, "<%s> Negotiated authentication method 0x%02X", conn->logprefix,
        method->method);
    if (method->callback == NULL)
        return 0;

    // Now let's begin authentication sub-negotiation
    socks_logger_prefix(conn, "AUTH");
    ctxt.username = NULL;
    ctxt.authdata = NULL;
    for (stage = 0;; stage++)
    {
        if ((len = socks_read(conn, conn->buffer, sizeof(conn->buffer))) < 0)
            return -1;
        ctxt.challenge = conn->buffer;
        ctxt.challenge_length = len;
        ctxt.response = conn->buffer;
        ctxt.response_maxlen = sizeof(conn->buffer);
        ctxt.response_length = 0;
        ret = method->callback(conn->logprefix, stage, &ctxt);
        if (ctxt.response_length > 0 &&
            socks_write(conn, ctxt.response, ctxt.response_length) < 0)
            return -1;
        if (ret == 0)
            break;
        if (ret < 0)
        {
            logger(LOG_WARNING, "<%s> Authentication failed", conn->logprefix);
            return -1;
        }
    }
    if (ctxt.username != NULL)
        logger(LOG_DEBUG, "<%s> Authenticated as user '%s'", conn->logprefix,
            ctxt.username);
    conn->username = ctxt.username;
    conn->authdata = ctxt.authdata;
    return 0;
}

/**
 * Errno code to SOCKS5 reply code
 */
static int socks_errno2reply(int err)
{
    switch (err)
    {
    case EAFNOSUPPORT:
    case EPROTONOSUPPORT:
    case EPROTOTYPE:
        return SOCKS_ERR_AF_UNSUPPORTED;
    case EACCES:
        return SOCKS_ERR_DISALLOWED;
    case ECONNREFUSED:
    case ECONNRESET:
        return SOCKS_ERR_CONN_REFUSED;
    case ENETUNREACH:
    case ENETDOWN:
        return SOCKS_ERR_NET_UNREACH;
    case ETIMEDOUT:
        return SOCKS_ERR_TTL_EXPIRED;
    case EHOSTUNREACH:
        return SOCKS_ERR_HOST_UNREACH;
    default:
        return SOCKS_ERR_GENERAL;
    }
}

/**
 * Resolve domain name
 */
static int socks_resolve(const socks_state_t *conn, const char *dname, size_t dlen, const void *pnum,
                         struct sockaddr_storage *dst)
{
    static const struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG,
    };
    char hostname[256], serv[16];
    uint16_t port;
    struct addrinfo *list;
    int ret;

    if (dlen >= sizeof(hostname))
    {
        logger(LOG_ERR, "<%s> FATAL: Domain length (%d) exceeds maximum (%d)", conn->logprefix,
            dlen, sizeof(hostname));
        exit(1);
    }
    memcpy(hostname, dname, dlen);
    hostname[dlen] = '\0';
    memcpy(&port, pnum, 2);
    snprintf(serv, sizeof(serv), "%u", ntohs(port)); // Yes, I know, that's stupid...
    if ((ret = getaddrinfo(hostname, serv, &hints, &list)) != 0)
    {
        logger(LOG_NOTICE, "<%s> Failed to resolve domain '%s': %s", conn->logprefix,
            hostname, gai_strerror(ret));
        return SOCKS_ERR_ADDR_INVALID;
    }
    if (list->ai_addrlen > sizeof(*dst))
    {
        logger(LOG_ERR, "<%s> FATAL: Address length (%d) exceeds maximum (%d) for domain '%s'",
            conn->logprefix, list->ai_addrlen, sizeof(*dst), hostname);
        exit(1);
    }
    memcpy(dst, list->ai_addr, list->ai_addrlen);
    freeaddrinfo(list);
    return 0;
}

/**
 * Copy data to/from destination
 */
static void socks_process_data(socks_state_t *conn, int destfd)
{
    fd_set rfds, efds;
    int nfds, ret;
    ssize_t len;

    socks_logger_prefix(conn, "DATA");
    for (;;)
    {
        FD_ZERO(&rfds);
        FD_SET(conn->socket, &rfds);
        FD_SET(destfd, &rfds);
        nfds = (conn->socket > destfd ? conn->socket : destfd) + 1;
        efds = rfds;
        if ((ret = select(nfds, &rfds, NULL, &efds, NULL)) == -1)
        {
            logger(LOG_WARNING, "<%s> Error while waiting: %m", conn->logprefix);
            break;
        }
        if (ret == 0)
            continue;
        if (FD_ISSET(conn->socket, &rfds))
        {
            if ((len = socks_read(conn, conn->buffer, sizeof(conn->buffer))) < 0)
                break;
            if (send(destfd, conn->buffer, len, 0) == -1)
            {
                logger(LOG_WARNING, "<%s> Error writing to server: %m", conn->logprefix);
                break;
            }
            continue;
        }
        if (FD_ISSET(destfd, &rfds))
        {
            if ((len = recv(destfd, conn->buffer, sizeof(conn->buffer), 0)) <= 0)
            {
                if (len < 0)
                    logger(LOG_WARNING, "<%s> Error reading from server: %m", conn->logprefix);
                break;
            }
            if (socks_write(conn, conn->buffer, len) < 0)
                break;
            continue;
        }
        if (FD_ISSET(conn->socket, &efds))
        {
            int err = 0;
            socklen_t errlen = sizeof(err);
            char errbuf[256] = "";

            getsockopt(conn->socket, SOL_SOCKET, SO_ERROR, &err, &errlen);
            strerror_r(err, errbuf, sizeof(errbuf));
            logger(LOG_WARNING, "<%s> Client socket error: [%d] %s", conn->logprefix,
                err, errbuf);
            continue;
        }
        if (FD_ISSET(destfd, &efds))
        {
            int err = 0;
            socklen_t errlen = sizeof(err);
            char errbuf[256] = "";

            getsockopt(destfd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            strerror_r(err, errbuf, sizeof(errbuf));
            logger(LOG_WARNING, "<%s> Server socket error: [%d] %s", conn->logprefix,
                err, errbuf);
            continue;
        }
    }
    logger(LOG_DEBUG, "<%s> Closing connection", conn->logprefix);
    close(destfd);
}

/**
 * Send a SOCKS5 reply.
 */
static int socks_send_reply(socks_state_t *conn, int errcode, const struct sockaddr *out)
{
    size_t len;

    conn->buffer[0] = SOCKS_VERSION5;
    conn->buffer[1] = errcode;
    conn->buffer[2] = 0x00;
    switch (out->sa_family)
    {
    default:
        // We shouldn't be here, because 'out' is initialized
        // from 'conn->localaddr'
        logger(LOG_WARNING, "<%s> Invalid AF in response address", conn->logprefix);
        return -1;
    case AF_INET:
        conn->buffer[3] = SOCKS_ADDR_IPV4;
        memcpy(&conn->buffer[4],     &((const struct sockaddr_in *)out)->sin_addr.s_addr, 4);
        memcpy(&conn->buffer[4 + 4], &((const struct sockaddr_in *)out)->sin_port,        2);
        len = 10;
        break;
    case AF_INET6:
        conn->buffer[3] = SOCKS_ADDR_IPV6;
        memcpy(&conn->buffer[4],      &((const struct sockaddr_in6 *)out)->sin6_addr.s6_addr, 16);
        memcpy(&conn->buffer[4 + 16], &((const struct sockaddr_in6 *)out)->sin6_port,          2);
        len = 22;
        break;
    }
    return socks_write(conn, conn->buffer, len);
}

/**
 * Process SOCKS5 CONNECT command.
 */
static int socks_process_connect(socks_state_t *conn, int *destfd)
{
    int err;

    logger(LOG_DEBUG, "<%s> Connecting...", conn->logprefix);
    if ((*destfd = socket(conn->server.ss_family, SOCK_STREAM, 0)) == -1)
    {
        err = errno;
        logger(LOG_WARNING, "<%s> Failed to open socket: %m", conn->logprefix);
        return socks_errno2reply(err);
    }
    if (connect(*destfd, (const struct sockaddr *)&conn->server, sizeof(conn->server)) == -1)
    {
        err = errno;
        logger(LOG_NOTICE, "<%s> Failed to connect: %m", conn->logprefix);
        close(*destfd);
        return socks_errno2reply(err);
    }
    logger(LOG_DEBUG, "<%s> Connected", conn->logprefix);
    return SOCKS_ERR_SUCCESS;
}

/**
 * Process SOCKS5 BIND command.
 */
static int socks_process_bind(socks_state_t *conn, struct sockaddr_storage *out, int *destfd)
{
    char srvhost[UTIL_ADDRSTRLEN + 1];
    struct sockaddr_storage srv;
    fd_set rfds, efds;
    socklen_t slen;
    int connfd = -1, err, nfds;

    // NOTE: We could, perhaps, use DST to choose an interface to bind;
    //       but it's hard to do portably, so we rely on the user to
    //       specufy external addresses to use, one per address family.
    switch (conn->server.ss_family)
    {
    case AF_INET:
        srv = BIND_ADDRESS_IP4;
        break;
    case AF_INET6:
        srv = BIND_ADDRESS_IP6;
        break;
    }
    if (srv.ss_family == AF_UNSPEC)
        return SOCKS_ERR_AF_UNSUPPORTED;
    logger(LOG_DEBUG, "<%s> Binding...", conn->logprefix);
    if ((connfd = socket(srv.ss_family, SOCK_STREAM, 0)) == -1)
    {
        err = errno;
        logger(LOG_ERR, "<%s> Failed to open listening socket: %m", conn->logprefix);
        return socks_errno2reply(err);
    }
    if (srv.ss_family == AF_INET6)
    {
        int val = 1;
        setsockopt(connfd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }
    if (bind(connfd, (const struct sockaddr *)&srv, sizeof(srv)) == -1)
    {
        err = errno;
        logger(LOG_ERR, "<%s> Failed to bind listening socket: %m", conn->logprefix);
ON_ERROR:
        close(connfd);
        return socks_errno2reply(err);
    }
    slen = sizeof(out);
    if (getsockname(connfd, (struct sockaddr *)&srv, &slen) == -1)
    {
        err = errno;
        logger(LOG_ERR, "<%s> Failed to get name of listening socket: %m", conn->logprefix);
        goto ON_ERROR;
    }
    util_decode_addr((const struct sockaddr *)&srv, sizeof(srv), srvhost, sizeof(srvhost));
    logger(LOG_DEBUG, "<%s> Waiting for connections on <%s>", conn->logprefix, srvhost);
    if (listen(connfd, 1) == -1)
    {
        err = errno;
        logger(LOG_ERR, "<%s> Failed to listen on listening socket: %m", conn->logprefix);
        goto ON_ERROR;
    }
    if (socks_send_reply(conn, SOCKS_ERR_SUCCESS, (struct sockaddr *)&srv) < 0)
    {
        close(connfd);
        return -1;
    }
    FD_ZERO(&rfds);
    FD_SET(conn->socket, &rfds);
    FD_SET(connfd, &rfds);
    nfds = (conn->socket > connfd ? conn->socket : connfd) + 1;
    efds = rfds;
    do
    {
        err = select(nfds, &rfds, NULL, &efds, NULL);
    }
    while (err == 0);
    if (err == -1)
    {
        err = errno;
        logger(LOG_WARNING, "<%s> Error waiting for connection: %m", conn->logprefix);
        goto ON_ERROR;
    }
    if (FD_ISSET(conn->socket, &rfds))
    {
        unsigned char b;
        if (socks_read(conn, &b, 1) > 0)
            logger(LOG_WARNING, "<%s> Extra data in control socket", conn->logprefix);
        logger(LOG_DEBUG, "<%s> Closing binding channel", conn->logprefix);
        close(connfd);
        return -1;
    }
    if (FD_ISSET(conn->socket, &efds))
    {
        logger(LOG_DEBUG, "<%s> Exception on control socket", conn->logprefix);
        close(connfd);
        return -1;
    }
    if (FD_ISSET(connfd, &efds))
    {
        logger(LOG_DEBUG, "<%s> Exception on listening socket", conn->logprefix);
        close(connfd);
        return -1;
    }
    if ((*destfd = accept(connfd, NULL, NULL)) == -1)
    {
        err = errno;
        logger(LOG_WARNING, "<%s> Error accepting connection: %m", conn->logprefix);
        goto ON_ERROR;
    }
    close(connfd);
    slen = sizeof(*out);
    if (getpeername(*destfd, (struct sockaddr *)out, &slen) == -1)
    {
        err = errno;
        logger(LOG_ERR, "<%s> Failed to get name of connected socket: %m", conn->logprefix);
        close(*destfd);
        goto ON_ERROR;
    }
    conn->server = *out;
    logger(LOG_DEBUG, "<%s> Connected", conn->logprefix);
    return SOCKS_ERR_SUCCESS;
}

/**
 * Process SOCKS5 request
 */
static int socks_process_request(socks_state_t *conn)
{
    ssize_t len;
    struct sockaddr_storage dst = { .ss_family = AF_UNSPEC }, out = conn->local;
    int errcode = SOCKS_ERR_SUCCESS, destfd = -1;

    socks_logger_prefix(conn, "CTRL");
    if ((len = socks_read(conn, conn->buffer, sizeof(conn->buffer))) < 0)
        return -1;
    if (len < 6 || conn->buffer[0] != SOCKS_VERSION5 || conn->buffer[2] != 0x00)
    {
        logger(LOG_WARNING, "<%s> Malformed request", conn->logprefix);
        return -1;
    }
    switch (conn->buffer[3]) // ATYP
    {
    default:
        logger(LOG_NOTICE, "<%s> Unrecognized address type 0x%02X", conn->logprefix,
            conn->buffer[3]);
        errcode = SOCKS_ERR_AF_UNSUPPORTED;
        goto ON_ERROR;
    case SOCKS_ADDR_IPV4: // IPv4
        if (len < 10)
        {
            logger(LOG_WARNING, "<%s> Malformed request (IPv4 len %d)", conn->logprefix,
                len);
            return -1; // Not enough data for IPv4 address
        }
        dst.ss_family = AF_INET;
        memcpy(&((struct sockaddr_in *)&dst)->sin_addr.s_addr, &conn->buffer[4], 4);
        memcpy(&((struct sockaddr_in *)&dst)->sin_port,        &conn->buffer[4 + 4], 2);
        break;
    case SOCKS_ADDR_DOMAIN: // Domain name
        if (len < 8 || conn->buffer[4] == 0 || (conn->buffer[4] + 7) > len)
        {
            logger(LOG_WARNING, "<%s> Malformed request (domain len %d/%d)", conn->logprefix,
                len, conn->buffer[4]);
            return -1; // Not enough data for domain name
        }
        if ((errcode = socks_resolve(conn, (const char *)&conn->buffer[5], conn->buffer[4],
                                     &conn->buffer[5 + conn->buffer[4]], &dst)) != 0)
            goto ON_ERROR;
        break;
    case SOCKS_ADDR_IPV6: // IPv6
        if (len < 22)
        {
            logger(LOG_WARNING, "<%s> Malformed request (IPv6 len %d)", conn->logprefix,
                len);
            return -1; // Not enough data for IPv6 address
        }
        dst.ss_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)&dst)->sin6_addr.s6_addr, &conn->buffer[4], 16);
        memcpy(&((struct sockaddr_in6 *)&dst)->sin6_port,         &conn->buffer[4 + 16], 2);
        break;
    }
    conn->server = dst;
    switch (conn->buffer[1]) // CMD
    {
    case SOCKS_CMD_ASSOCIATE:
        // TODO: UDP ASSOCIATE not implemented yet.
    default:
        // NOTE: UDP ASSOCIATE is not implemented yet
        logger(LOG_NOTICE, "<%s> Unknown command 0x%02X", conn->logprefix,
            conn->buffer[1]);
        errcode = SOCKS_ERR_CMD_UNSUPPORTED;
        break;
    case SOCKS_CMD_CONNECT:
        socks_logger_prefix(conn, "CONNECT");
        errcode = socks_process_connect(conn, &destfd);
        break;
    case SOCKS_CMD_BIND:
        socks_logger_prefix(conn, "BIND");
        errcode = socks_process_bind(conn, &out, &destfd);
        if (errcode < 0)
            return -1;
        break;
    }
ON_ERROR:
    if (socks_send_reply(conn, errcode, (struct sockaddr *)&out) < 0)
        return -1;
    if (errcode != SOCKS_ERR_SUCCESS)
        return -1;
    if (destfd != -1)
        socks_process_data(conn, destfd);
    return 0;
}

/**
 * Thread function for client connection
 */
static void *socks_connection_thread(void *arg)
{
    socks_state_t conn = {
        .socket    = (int)(intptr_t)arg,
        .username  = NULL,
        .authdata  = NULL,
        .local     = { .ss_family = AF_UNSPEC },
        .client    = { .ss_family = AF_UNSPEC },
        .server    = { .ss_family = AF_UNSPEC },
        .logprefix = "",
    };
    socklen_t addrlen;

    addrlen = sizeof(conn.client);
    getpeername(conn.socket, (struct sockaddr *)&conn.client, &addrlen);
    addrlen = sizeof(conn.local);
    getsockname(conn.socket, (struct sockaddr *)&conn.local, &addrlen);

    if (socks_negotiate_method(&conn) == 0)
        socks_process_request(&conn);
    close(conn.socket);
    if (conn.authdata != NULL)
        free(conn.authdata);
    return NULL;
}

/**
 * Set single interface address to use for BIND and UDP ASSOCIATE commands.
 */
static int socks_set_bind_ifaddr(const char *name, int family, unsigned *pmask,
                                 const struct sockaddr *addr, int addrlen)
{
    struct sockaddr_storage *ss;
    int deflen = 0;
    unsigned m = 0;

    switch (family)
    {
    case AF_INET:
        ss = &BIND_ADDRESS_IP4;
        deflen = sizeof(struct sockaddr_in);
        m = 0x01;
        break;
    case AF_INET6:
        ss = &BIND_ADDRESS_IP6;
        deflen = sizeof(struct sockaddr_in6);
        m = 0x02;
        break;
    default:
        return -1;
    }
    if (addrlen == -1)
        addrlen = deflen;
    if (addrlen > (int)sizeof(*ss))
    {
        logger(LOG_ERR, "FATAL: Address length (%d) exceeds maximum (%d) for '%s'",
            addrlen, sizeof(*ss), name);
        exit(1);
    }
    if (ss->ss_family != AF_UNSPEC)
    {
        if (pmask != NULL && (*pmask & m) != 0)
            return -1;
    }
    if (pmask != NULL)
        *pmask |= m;
    memset(ss, 0, sizeof(*ss));
    memcpy(ss, addr, addrlen);
    return 0;
}

/**
 * Set interface addresses to use for BIND and UDP ASSOCIATE commands.
 */
int socks_set_bind_if(const char *host)
{
    int ret;
    struct addrinfo *addrlist = NULL, *ptr;
    static const struct addrinfo hints = {
        .ai_flags = AI_PASSIVE|AI_ADDRCONFIG,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC,
    };

#if HAVE_IFADDRS_SUPPORT
    if (host != NULL && host[0] == '@')
    {
        struct ifaddrs *ifa_list = NULL;
        const struct ifaddrs *ifa;
        unsigned mask = 0;

        if (getifaddrs(&ifa_list) != 0)
        {
            logger(LOG_ERR, "Failed to get list of interface addresses: %m");
            return -1;
        }
        for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (strcmp(ifa->ifa_name, &host[1]) != 0 || ifa->ifa_addr == NULL)
                continue;
            socks_set_bind_ifaddr(host, ifa->ifa_addr->sa_family, &mask, ifa->ifa_addr, -1);
        }
        freeifaddrs(ifa_list);
        if (mask == 0)
            logger(LOG_WARNING, "No addresses found for interface '%s'", &host[1]);
        return 0;
    }
#endif
    if ((ret = getaddrinfo(host, NULL, &hints, &addrlist)) != 0)
    {
        logger(LOG_ERR, "Failed to resolve bind address: %s", gai_strerror(ret));
        return -1;
    }
    for (ptr = addrlist; ptr != NULL; ptr = ptr->ai_next)
        socks_set_bind_ifaddr(host, ptr->ai_family, NULL, ptr->ai_addr, ptr->ai_addrlen);
    freeaddrinfo(addrlist);
    return 0;
}

/**
 * Report which addresses we are using for BIND and UDP ASSOCIATE.
 */
void socks_show_bind_if()
{
    static const struct sockaddr_storage *LIST[] = { &BIND_ADDRESS_IP4, &BIND_ADDRESS_IP6, NULL };
    char hostaddr[UTIL_ADDRSTRLEN];
    const struct sockaddr_storage **ssp;

    for (ssp = LIST; *ssp != NULL; ssp++)
    {
        if ((*ssp)->ss_family == AF_UNSPEC)
            continue;
        util_decode_addr((const struct sockaddr *)*ssp, sizeof(**ssp), hostaddr, sizeof(hostaddr));
        logger(LOG_INFO, "Binding enabled on address <%s>", hostaddr);
    }
}

/**
 * Listen at all addresses of given host, return parameters for select(3)
 */
int socks_listen_at(const char *host, const char *service, fd_set *fds)
{
    int ret, nfds = 0;
    struct addrinfo *addrlist = NULL, *ptr;
    static const struct addrinfo hints = {
        .ai_flags = AI_PASSIVE|AI_ADDRCONFIG,
        .ai_socktype = SOCK_STREAM,
        .ai_family = AF_UNSPEC,
    };

    FD_ZERO(fds);
    if ((ret = getaddrinfo(host, service, &hints, &addrlist)) != 0)
    {
        logger(LOG_ERR, "Failed to resolve listen address: %s", gai_strerror(ret));
        return -1;
    }
    for (ptr = addrlist; ptr != NULL; ptr = ptr->ai_next)
    {
        int sock, val;
        char hostaddr[UTIL_ADDRSTRLEN];

        util_decode_addr(ptr->ai_addr, ptr->ai_addrlen, hostaddr, sizeof(hostaddr));
        if ((sock = socket(ptr->ai_family, SOCK_STREAM, 0)) == -1)
        {
            logger(LOG_ERR, "Failed to open socket for address <%s>: %m", hostaddr);
ON_ERROR:
            freeaddrinfo(addrlist);
            return -1;
        }
        if (ptr->ai_family == AF_INET6)
        {
            val = 1;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
        }
        val = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        if (bind(sock, ptr->ai_addr, ptr->ai_addrlen) == -1)
        {
            logger(LOG_ERR, "Failed to bind address <%s>: %m", hostaddr);
            goto ON_ERROR;
        }
        if (listen(sock, SOMAXCONN) == -1)
        {
            logger(LOG_ERR, "Failed to listen on address <%s>: %m", hostaddr);
            goto ON_ERROR;
        }
        logger(LOG_INFO, "Listening on address <%s>", hostaddr);
        FD_SET(sock, fds);
        if (sock >= nfds)
            nfds = sock + 1;
    }
    freeaddrinfo(addrlist);
    return nfds;
}

/**
 * Accept incoming connections on all listened addresses
 */
void socks_accept_loop(int nfds, const fd_set *fds)
{
    pthread_attr_t thr_attr;

    pthread_attr_init(&thr_attr);
    pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);
    for (;;)
    {
        fd_set rfds = *fds, efds = *fds;
        int ret, sock, rsock;
        pthread_t thr;

        if ((ret = select(nfds, &rfds, NULL, &efds, NULL)) == -1)
        {
            logger(LOG_ERR, "Error waiting for connections: %m");
            break;
        }
        if (ret == 0)
            continue;
        for (sock = 3; sock < nfds; sock++)
        {
            if (FD_ISSET(sock, &efds))
            {
                int err = 0;
                socklen_t errlen = sizeof(err);
                char errbuf[256] = "";

                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
                strerror_r(err, errbuf, sizeof(errbuf));
                logger(LOG_WARNING, "Listen socket error: [%d] %s", err, errbuf);
                continue;
            }
            if (!FD_ISSET(sock, &rfds))
                continue;
            if ((rsock = accept(sock, NULL, NULL)) == -1)
            {
                logger(LOG_WARNING, "Error accepting connection: %m");
                continue;
            }
            if ((ret = pthread_create(&thr, &thr_attr, socks_connection_thread, (void *)(intptr_t)rsock)) != 0)
            {
                char errbuf[256] = "";

                strerror_r(ret, errbuf, sizeof(errbuf));
                logger(LOG_WARNING, "Failed to create connection thread: [%d] %s", ret, errbuf);
                close(rsock);
            }
        }
    }
}

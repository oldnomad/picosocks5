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
#include <pthread.h>
#include "socks5.h"
#include "auth.h"
#include "logger.h"
#include "util.h"
#include "socks5bits.h"

typedef struct {
    int socket;                        // Client socket
    const void *auth;                  // Authenticated user (if any)
    struct sockaddr_storage localaddr; // Local address and port
    char peername[UTIL_ADDRSTRLEN];    // Client's socket name
    char destname[UTIL_ADDRSTRLEN];    // Server's socket name
} socks_state_t;

/**
 * Negotiate authentication method and perform corresponding
 * sub-negotiation stages
 */
static int socks_negotiate_method(socks_state_t *conn)
{
    unsigned char buffer[1024]; // Is it enough for most sub-negotiations?
    ssize_t len;
    int ret, stage;
    const auth_method_t *method;
    auth_context_t ctxt;

    if ((len = recv(conn->socket, buffer, sizeof(buffer), 0)) <= 0)
    {
        if (len < 0)
            logger(LOG_WARNING, "<%s> Error receiving initial offer: %m",
                conn->peername);
        return -1;
    }
    if (len < 3 || buffer[0] != SOCKS_VERSION5 || buffer[1] == 0 || (buffer[1] + 2) > len)
    {
        logger(LOG_WARNING, "<%s> Malformed initial offer",
            conn->peername);
        return -1;
    }
    method = auth_negotiate_method(&buffer[2], buffer[1]);
    buffer[0] = SOCKS_VERSION5;
    buffer[1] = method == NULL ? SOCKS_AUTH_INVALID : method->method;
    if (send(conn->socket, buffer, 2, 0) == -1)
    {
        logger(LOG_WARNING, "<%s> Error sending initial offer: %m",
            conn->peername);
        return -1;
    }
    if (method == NULL)
    {
        logger(LOG_NOTICE, "<%s> No authentication method available",
            conn->peername);
        return -1;
    }
    logger(LOG_DEBUG, "<%s> Negotiated authentication method 0x%02X",
        conn->peername, method->method);
    if (method->callback == NULL)
        return 0;
    // Now let's begin authentication sub-negotiation
    ctxt.auth = NULL;
    for (stage = 0;; stage++)
    {
        if ((len = recv(conn->socket, buffer, sizeof(buffer), 0)) <= 0)
        {
            if (len < 0)
                logger(LOG_WARNING, "<%s> Error receiving auth packet: %m",
                    conn->peername);
            return -1;
        }
        ctxt.challenge = buffer;
        ctxt.challenge_length = len;
        ctxt.response = buffer;
        ctxt.response_maxlen = sizeof(buffer);
        ctxt.response_length = 0;
        ret = method->callback(conn->peername, stage, &ctxt);
        if (ctxt.response_length > 0)
        {
            if (send(conn->socket, buffer, ctxt.response_length, 0) == -1)
            {
                logger(LOG_WARNING, "<%s> Error sending auth response: %m",
                    conn->peername);
                return -1;
            }
        }
        if (ret == 0)
            break;
        if (ret < 0)
        {
            logger(LOG_WARNING, "<%s> Authentication failed",
                conn->peername);
            return -1;
        }
    }
    if (ctxt.auth != NULL)
        logger(LOG_DEBUG, "<%s> Authenticated as user '%s'",
            conn->peername, auth_get_username(ctxt.auth));
    conn->auth = ctxt.auth;
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
 * Process SOCKS5 request
 */
static int socks_process_request(socks_state_t *conn)
{
    unsigned char buffer[256 + 6];
    ssize_t len;
    struct sockaddr_storage dst = { .ss_family = AF_UNSPEC }, out = conn->localaddr;
    int errcode = SOCKS_ERR_SUCCESS, destfd = -1;

    if ((len = recv(conn->socket, buffer, sizeof(buffer), 0)) <= 0)
    {
        if (len < 0)
            logger(LOG_WARNING, "<%s> Error receiving request: %m",
                conn->peername);
        return -1;
    }
    if (len < 6 || buffer[0] != SOCKS_VERSION5 || buffer[2] != 0x00)
    {
        logger(LOG_WARNING, "<%s> Malformed request: [%d] %02x %02x %02x %02x",
            conn->peername, len, buffer[0], buffer[1], buffer[2], buffer[3]);
        return -1;
    }
    switch (buffer[3]) // ATYP
    {
    default:
        logger(LOG_NOTICE, "<%s> Unrecognized address type 0x%02X",
            conn->peername, buffer[3]);
        errcode = SOCKS_ERR_AF_UNSUPPORTED;
        goto ON_ERROR;
    case SOCKS_ADDR_IPV4: // IPv4
        if (len < 10)
        {
            logger(LOG_WARNING, "<%s> Malformed request (IPv4 len %d)",
                conn->peername, len);
            return -1; // Not enough data for IPv4 address
        }
        dst.ss_family = AF_INET;
        memcpy(&((struct sockaddr_in *)&dst)->sin_addr.s_addr, &buffer[4], 4);
        memcpy(&((struct sockaddr_in *)&dst)->sin_port, &buffer[4 + 4], 2);
        break;
    case SOCKS_ADDR_DOMAIN: // Domain name
        if (len < 8 || buffer[4] == 0 || (buffer[4] + 7) > len)
        {
            logger(LOG_WARNING, "<%s> Malformed request (domain len %d/%d)",
                conn->peername, len, buffer[4]);
            return -1; // Not enough data for domain name
        }
        {
            static const struct addrinfo hints = {
                .ai_flags = AI_ADDRCONFIG,
            };
            char hostname[256], serv[16];
            uint16_t port;
            struct addrinfo *list;
            int ret;

            memcpy(hostname, &buffer[5], buffer[4]);
            hostname[buffer[4]] = '\0';
            memcpy(&port, &buffer[5 + buffer[4]], 2);
            snprintf(serv, sizeof(serv), "%u", ntohs(port)); // Yes, I know, that's stupid...
            if ((ret = getaddrinfo(hostname, serv, &hints, &list)) != 0)
            {
                logger(LOG_NOTICE, "<%s> Failed to resolve domain '%s': %s",
                    conn->peername, hostname, gai_strerror(ret));
                errcode = SOCKS_ERR_ADDR_INVALID;
                goto ON_ERROR;
            }
            if (list->ai_addrlen > sizeof(dst))
            {
                logger(LOG_CRIT, "<%s> FATAL: Address length (%d) exceeds maximum (%d) for domain '%s'",
                    conn->peername, list->ai_addrlen, sizeof(dst), hostname);
                exit(1);
            }
            memcpy(&dst, list->ai_addr, list->ai_addrlen);
            freeaddrinfo(list);
        }
        break;
    case SOCKS_ADDR_IPV6: // IPv6
        if (len < 22)
        {
            logger(LOG_WARNING, "<%s> Malformed request (IPv6 len %d)",
                conn->peername, len);
            return -1; // Not enough data for IPv6 address
        }
        dst.ss_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)&dst)->sin6_addr.s6_addr, &buffer[4], 16);
        memcpy(&((struct sockaddr_in6 *)&dst)->sin6_port, &buffer[4 + 16], 2);
        break;
    }
    util_decode_addr((struct sockaddr *)&dst, sizeof(dst), conn->destname, sizeof(conn->destname));
    switch (buffer[1]) // CMD
    {
    case SOCKS_CMD_BIND:
    case SOCKS_CMD_ASSOCIATE:
    default:
        // NOTE: BIND and UDP ASSOCIATE/BIND are not implemented yet
        logger(LOG_NOTICE, "<%s> Unknown command 0x%02X",
            conn->peername, buffer[1]);
        errcode = SOCKS_ERR_CMD_UNSUPPORTED;
        break;
    case SOCKS_CMD_CONNECT:
        logger(LOG_DEBUG, "<%s> Connecting to <%s>",
            conn->peername, conn->destname);
        if ((destfd = socket(dst.ss_family, SOCK_STREAM, 0)) == -1)
        {
            int err = errno;
            logger(LOG_WARNING, "<%s> Failed to open socket: %m",
                conn->peername);
            errcode = socks_errno2reply(err);
            break;
        }
        if (connect(destfd, (struct sockaddr *)&dst, sizeof(dst)) == -1)
        {
            int err = errno;
            logger(LOG_NOTICE, "<%s | %s> Failed to connect: %m",
                conn->peername, conn->destname);
            close(destfd);
            errcode = socks_errno2reply(err);
            break;
        }
        logger(LOG_DEBUG, "<%s | %s> Connected",
            conn->peername, conn->destname);
        break;
    }
ON_ERROR:
    buffer[0] = SOCKS_VERSION5;
    buffer[1] = errcode;
    buffer[2] = 0x00;
    switch (out.ss_family)
    {
    default:
        // We shouldn't be here, because 'out' is initialized
        // from 'conn->localaddr'; anyway, let's just preserve
        // the original address.
        logger(LOG_WARNING, "<%s> Invalid AF in response address (internal error)",
            conn->peername);
        break;
    case AF_INET:
        buffer[3] = SOCKS_ADDR_IPV4;
        memcpy(&buffer[4], &((struct sockaddr_in *)&out)->sin_addr.s_addr, 4);
        memcpy(&buffer[4 + 4], &((struct sockaddr_in *)&out)->sin_port, 2);
        len = 10;
        break;
    case AF_INET6:
        buffer[3] = SOCKS_ADDR_IPV6;
        memcpy(&buffer[4], &((struct sockaddr_in6 *)&out)->sin6_addr.s6_addr, 16);
        memcpy(&buffer[4 + 16], &((struct sockaddr_in6 *)&out)->sin6_port, 2);
        len = 22;
        break;
    }
    if (send(conn->socket, buffer, len, 0) == -1)
    {
        logger(LOG_WARNING, "<%s> Error sending reply: %m",
            conn->peername);
        return -1;
    }
    if (errcode != SOCKS_ERR_SUCCESS)
        return -1;
    if (destfd != -1)
    {
        for (;;)
        {
            fd_set rfds, efds;
            int nfds, ret;

            FD_ZERO(&rfds);
            FD_SET(conn->socket, &rfds);
            FD_SET(destfd, &rfds);
            nfds = (conn->socket > destfd ? conn->socket : destfd) + 1;
            efds = rfds;
            if ((ret = select(nfds, &rfds, NULL, &efds, NULL)) == -1)
            {
                logger(LOG_WARNING, "<%s | %s> Error while waiting: %m",
                    conn->peername, conn->destname);
                break;
            }
            if (ret == 0)
                continue;
            if (FD_ISSET(conn->socket, &rfds))
            {
                if ((len = recv(conn->socket, buffer, sizeof(buffer), 0)) <= 0)
                {
                    if (len < 0)
                        logger(LOG_WARNING, "<%s | %s> Error reading from client: %m",
                            conn->peername, conn->destname);
                    break;
                }
                if (send(destfd, buffer, len, 0) == -1)
                {
                    logger(LOG_WARNING, "<%s | %s> Error writing to server: %m",
                        conn->peername, conn->destname);
                    break;
                }
                continue;
            }
            if (FD_ISSET(destfd, &rfds))
            {
                if ((len = recv(destfd, buffer, sizeof(buffer), 0)) <= 0)
                {
                    if (len < 0)
                        logger(LOG_WARNING, "<%s | %s> Error reading from server: %m",
                            conn->peername, conn->destname);
                    break;
                }
                if (send(conn->socket, buffer, len, 0) == -1)
                {
                    logger(LOG_WARNING, "<%s | %s> Error writing to client: %m",
                        conn->peername, conn->destname);
                    break;
                }
                continue;
            }
            if (FD_ISSET(conn->socket, &efds))
            {
                int err = 0;
                socklen_t errlen = sizeof(err);
                char errbuf[256] = "";

                getsockopt(conn->socket, SOL_SOCKET, SO_ERROR, &err, &errlen);
                strerror_r(err, errbuf, sizeof(errbuf));
                logger(LOG_WARNING, "<%s | %s> Client socket error: [%d] %s",
                    conn->peername, conn->destname, err, errbuf);
                continue;
            }
            if (FD_ISSET(destfd, &efds))
            {
                int err = 0;
                socklen_t errlen = sizeof(err);
                char errbuf[256] = "";

                getsockopt(destfd, SOL_SOCKET, SO_ERROR, &err, &errlen);
                strerror_r(err, errbuf, sizeof(errbuf));
                logger(LOG_WARNING, "<%s | %s> Server socket error: [%d] %s",
                    conn->peername, conn->destname, err, errbuf);
                continue;
            }
        }
        logger(LOG_DEBUG, "<%s | %s> Closing connection",
            conn->peername, conn->destname);
        close(destfd);
    }
    return 0;
}

/**
 * Thread function for client connection
 */
static void *socks_connection_thread(void *arg)
{
    socks_state_t conn = {
        .socket = (int)(intptr_t)arg,
        .auth = NULL,
        .localaddr = { .ss_family = AF_UNSPEC },
        .peername = "",
        .destname = "",
    };

    {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        if (getpeername(conn.socket, (struct sockaddr *)&addr, &addrlen) == 0)
            util_decode_addr((struct sockaddr *)&addr, addrlen,
                conn.peername, sizeof(conn.peername));
        addrlen = sizeof(conn.localaddr);
        getsockname(conn.socket, (struct sockaddr *)&conn.localaddr, &addrlen);
    }
    if (socks_negotiate_method(&conn) == 0)
        socks_process_request(&conn);
    close(conn.socket);
    return NULL;
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
        int sock;
        char hostaddr[UTIL_ADDRSTRLEN];

        util_decode_addr(ptr->ai_addr, ptr->ai_addrlen, hostaddr, sizeof(hostaddr));
        if ((sock = socket(ptr->ai_family, SOCK_STREAM, 0)) == -1)
        {
            logger(LOG_ERR, "Failed to open socket for address <%s>: %m", hostaddr);
            return -1;
        }
        if (ptr->ai_family == AF_INET6)
        {
            int on = 1;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        }
        if (bind(sock, ptr->ai_addr, ptr->ai_addrlen) == -1)
        {
            logger(LOG_ERR, "Failed to bind address <%s>: %m", hostaddr);
            return -1;
        }
        if (listen(sock, SOMAXCONN) == -1)
        {
            logger(LOG_ERR, "Failed to listen on address <%s>: %m", hostaddr);
            return -1;
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

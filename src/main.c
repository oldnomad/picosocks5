/**
 * @file
 * Main procedure.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "socks5.h"
#include "crypto.h"
#include "logger.h"
#include "cmdline.h"

/**
 * Daemon configuration.
 */
static daemon_config_t CONFIG = {
    .nofork         = 0,
    .logmode        = 0,
    .loglevel       = -1,
    .drop_uid       = -1,
    .drop_gid       = -1,
    .listen_host    = NULL,
    .listen_service = NULL,
};
/**
 * Signal that resulted in exit.
 */
static volatile sig_atomic_t EXIT_SIGNO = 0;

/**
 * Fork to background.
 *
 * @param uid UID to set.
 * @param gid GID to set.
 */
static void daemonize(uid_t uid, gid_t gid)
{
    static sigset_t sigmask;
    pid_t pid;
    int null_fd;

    if (getppid() == 1) // Our parent is init(1), bail out
        return;
    switch (pid = fork())
    {
    default:
        printf("Started daemon at PID %d\n", pid);
        exit(0);
    case 0:
        break;
    case -1:
        logger(LOG_ERR, "Unable to fork: %m");
        exit(1);
    }
    setsid();
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if ((null_fd = open("/dev/null", O_RDWR)) != -1)
    {
        dup2(null_fd, 0);
        dup2(null_fd, 1);
        dup2(null_fd, 2);
        close(null_fd);
    }
    if (getuid() != 0) // Not root, cannot change gid/uid
        return;
    if (gid != (gid_t)-1 && setgid(gid) != 0)
    {
        logger(LOG_ERR, "Failed to set GID %u: %m", gid);
        exit(1);
    }
    if (uid != (uid_t)-1 && setuid(uid) != 0)
    {
        logger(LOG_ERR, "Failed to set UID %u: %m", uid);
        exit(1);
    }
}

/**
 * Fatal signal handler.
 *
 * @param signo signal number.
 */
static void signal_handler(int signo)
{
    int fd;

    EXIT_SIGNO = signo;
    for (fd = 3; fd < FD_SETSIZE; fd++)
        if (fcntl(fd, F_GETFD) != -1)
            close(fd);
}

/**
 * Main procedure.
 *
 * @param argc number od command line parameters.
 * @param argv array od command line parameters.
 * @return exit code.
 */
int main(int argc, char **argv)
{
    int nfds;
    fd_set fds;
    struct sigaction sa = {
        .sa_flags   = 0,
        .sa_handler = signal_handler,
    };

    CONFIG.progname = argv[0];
    cmdline_process(argc, argv, &CONFIG);
    logger_init(CONFIG.nofork, CONFIG.logmode, CONFIG.loglevel);
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    crypto_init();
    if ((nfds = socks_listen_at(CONFIG.listen_host, CONFIG.listen_service, &fds)) < 0)
        exit(1);
    socks_show_config();
    if (CONFIG.nofork == 0)
        daemonize(CONFIG.drop_gid, CONFIG.drop_uid);
    logger(LOG_INFO, "Running %s", cmdline_version());
    socks_accept_loop(nfds, &fds);
    if (EXIT_SIGNO != 0)
        logger(LOG_ERR, "Received signal %d, exiting", EXIT_SIGNO);
    else
        logger(LOG_INFO, "Exiting");
    return 0;
}

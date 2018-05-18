#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <getopt.h>
#include "socks5.h"
#include "authfile.h"
#include "authuser.h"
#include "logger.h"
#include "util.h"

/**
 * Fork to background.
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
    if (gid != (gid_t)-1)
        setgid(gid);
    if (uid != (uid_t)-1)
        setuid(uid);
}


static const char SHORT_OPTS[] = "a:Au:g:L:v:h";
static const struct option LONG_OPTS[] = {
    { "nofork",      0, NULL, 1000 },
    { "logmode",     1, NULL, 'L'  },
    { "loglevel",    1, NULL, 'v'  },
    { "auth",        1, NULL, 'a'  },
    { "anonymous",   0, NULL, 'A'  },
    { "user",        1, NULL, 'u'  },
    { "group",       1, NULL, 'g'  },
    { "help",        0, NULL, 'h'  },
    { NULL }
};
static const char OPTIONS_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Options:\n\n"
    "    -a [<format>:]<secrets-file>, --auth=[<format>:]<secrets-file>\n"
    "        Secrets file for authentication. If format is not\n"
    "        explicitly specified, \"password\" is implied. See below\n"
    "        about supported formats. Note that defining a secrets file\n"
    "        with users available for non-anonymous authentication\n"
    "        disables anonymous access, unless --anonymous is also\n"
    "        specified.\n\n"
    "    -A, --anonymous\n"
    "        Allow anonymous access even if there is a non-anonymous\n"
    "        method available.\n\n"
    "    -u <user>, --user=<user>\n"
    "    -g <group>, --group=<group>\n"
    "        Specify non-privileged user and group to use for daemon\n"
    "        execution; both <user> and <group> can be specified either\n"
    "        as names, or as numeric values, decimal, octal, or\n"
    "        hexadecimal (in C notation).\n\n"
    "    --nofork\n"
    "        Do not fork the daemon to background. This option also\n"
    "        changes the default logging mode from \"syslog\" to \"stderr\".\n\n"
    "        Note that the daemon won't fork if its parent is init\n"
    "        process (PID 1).\n\n"
    "    -L <mode>, --logmode=<mode>\n"
    "        Specify logging mode. Supported modes are:\n"
    "            syslog   - log to syslog (default unless --nofork);\n"
    "            stderr   - log to stderr (implies --nofork);\n"
    "            combined - log to both syslog and stderr (implies\n"
    "                       --nofork).\n\n"
    "    -v <level>, --loglevel=<level>\n"
    "        Specify maximum logging verbosity level. Supported levels\n"
    "        are:\n"
    "            err      - only fatal errors;\n"
    "            warn     - also protocol errors;\n"
    "            notice   - also important protocol disruptions;\n"
    "            info     - also informational messages (default);\n"
    "            debug    - also debugging messages;\n"
    "            none     - suppress logging completely.\n\n"
    "    -h, --help\n"
    "        Print usage information and exit.\n";
static const char ARG_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Listen address can be specified as a literal address (IPv4 or\n"
    "IPv6), or a host name. Listen address \"*\" means listening on\n"
    "all available interfaces.\n\n"
    "Listen port can be specified as a literal port number, or a\n"
    "service name.\n\n"
    "By default \"*:1080\" is used.\n";
static const char AUTHFILE_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Authentication file formats:\n\n"
    "    password\n"
    "        File is a text file, each line containing user name and\n"
    "        password hash separated by semicolon (':'). No empty lines\n"
    "        or comments are allowed.\n\n"
    "        Password hash can be any type of salted hash supported by\n"
    "        your GLibC version (see man 3 crypt). All versions of GLibC\n"
    "        support MD5-crypt (prefix \"$1$\"), as produced, for example,\n"
    "        by command \"openssl passwd -1\". Recent GLibC versions also\n"
    "        support SHA-256 (prefix \"$5$\"), SHA-512 (prefix \"$6$\"),\n"
    "        and, in some distributions, Blowfish (prefix \"$2a$\").\n";

static void usage(const char *bin_name)
{
    printf("Usage: %s [<option>...] [<listen-address>:<listen-port>]\n\n"
           "%s\n%s\n%s",
           bin_name, ARG_DESC, OPTIONS_DESC, AUTHFILE_DESC);
    exit(2);
}

int main(int argc, char **argv)
{
    int nofork = 0, logmode = 0, loglevel = -1;
    gid_t drop_gid = -1;
    uid_t drop_uid = -1;
    const char *listen_host = NULL;
    const char *listen_service = "1080";
    int opt, nfds;
    fd_set fds;

    while ((opt = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1)
    {
        switch (opt)
        {
        case '?': // Error in options
            exit(1);
            break;
        case 1000: // --nofork
            nofork = 1;
            break;
        case 'L': // --logmode=<mode>
            if ((logmode = logger_name2mode(optarg)) < 0)
            {
                fprintf(stderr, "Unknown logging mode '%s'\n", optarg);
                exit(1);
            }
            if (logger_need_nofork(logmode))
                nofork = 1;
            break;
        case 'v': // --loglevel=<level>
            if ((loglevel = logger_name2level(optarg)) < 0)
            {
                fprintf(stderr, "Unknown logging level '%s'\n", optarg);
                exit(1);
            }
            break;
        case 'a': // --auth=[<format>:]<secrets-file>
            authfile_parse(optarg);
            break;
        case 'A':
            authuser_anon_allow(1);
            break;
        case 'u': // --user=<uid>
            if ((drop_uid = util_parse_user(optarg)) == (uid_t)-1)
            {
                fprintf(stderr, "Cannot find user '%s'\n", optarg);
                exit(1);
            }
            break;
        case 'g': // --group=<gid>
            if ((drop_gid = util_parse_group(optarg)) == (gid_t)-1)
            {
                fprintf(stderr, "Cannot find group '%s'\n", optarg);
                exit(1);
            }
            break;
        case 'h': // --help
            usage(argv[0]);
            break;
        }
    }
    if (optind < argc)
    {
        const char *arg = argv[optind];
        size_t alen = strlen(arg);

        if ((optind + 1) < argc)
            usage(argv[0]);
        if (alen == 0)
        {
            fprintf(stderr, "Empty listen address\n");
            exit(1);
        }
        listen_host = arg;
        if (arg[alen - 1] != ']') // Not literal IPv6
        {
            char *sp = strrchr(arg, ':');
            if (sp != NULL)
            {
                // We modify argv; that's not pretty, but allowed
                *sp++ = '\0';
                listen_service = sp;
            }
        }
        if (listen_host[0] == '\0' ||
            (listen_host[0] == '*' && listen_host[1] == '\0'))
            listen_host = NULL;
    }
    logger_init(nofork, logmode, loglevel);
    if ((nfds = socks_listen_at(listen_host, listen_service, &fds)) < 0)
        exit(1);
    if (nofork == 0)
        daemonize(drop_gid, drop_uid);
    logger(LOG_INFO, "Running %s, built on %s %s", PACKAGE_STRING, __DATE__, __TIME__);
    socks_accept_loop(nfds, &fds);
    logger(LOG_INFO, "Exiting");
    return 0;
}

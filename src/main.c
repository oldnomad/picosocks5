#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <ctype.h>
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
#include "crypto.h"
#include "logger.h"
#include "util.h"

#define BUILD_TIMESTAMP __DATE__ " " __TIME__

#define DEFAULT_LISTEN_SERVICE "1080"

/**
 * Daemon configuration.
 */
static struct cfg {
    int   nofork;         // Don't fork to background
    int   logmode;        // Logging mode (syslog and/or stderr)
    int   loglevel;       // Logging verbosity level
    uid_t drop_uid;       // UID to drop to, or -1
    gid_t drop_gid;       // GID to drop to, or -1
    char *listen_host;    // Address to listen on, or null for all
    char *listen_service; // Port to listen on, or null for default
} CONFIG = {
    .nofork         = 0,
    .logmode        = 0,
    .loglevel       = -1,
    .drop_uid       = -1,
    .drop_gid       = -1,
    .listen_host    = NULL,
    .listen_service = NULL,
};

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
    if (gid != (gid_t)-1 && setgid(gid) != 0)
    {
        logger(LOG_ERR, "Failed to set GID %d: %m", gid);
        exit(1);
    }
    if (uid != (uid_t)-1 && setuid(uid) != 0)
    {
        logger(LOG_ERR, "Failed to set UID %d: %m", uid);
        exit(1);
    }
}


static const char SHORT_OPTS[] = "c:a:Au:g:L:v:hV";
static const struct option LONG_OPTS[] = {
    { "config",      1, NULL, 'c'  },
    { "nofork",      0, NULL, 1000 },
    { "logmode",     1, NULL, 'L'  },
    { "loglevel",    1, NULL, 'v'  },
    { "auth",        1, NULL, 'a'  },
    { "anonymous",   0, NULL, 'A'  },
    { "user",        1, NULL, 'u'  },
    { "group",       1, NULL, 'g'  },
    { "help",        0, NULL, 'h'  },
    { "version",     0, NULL, 'V'  },
    { NULL }
};
static const char OPTIONS_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Options:\n\n"
    "    -c <config-file>\n"
    "        Read options from specified configuration file. Note that\n"
    "        command-line options are processed in order, so options\n"
    "        specified in the file will override options specified in\n"
    "        the command line earlier, and will be overridden by options\n"
    "        specified in the command line later.\n\n"
    "    -a [<format>:]<secrets-file>, --auth=[<format>:]<secrets-file>\n"
    "        Secrets file for authentication. If format is not\n"
    "        explicitly specified, \"password\" is implied.\n\n"
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
    "        Print usage information and exit.\n\n"
    "    -V, --version\n"
    "        Print daemon version and exit.\n";
static const char ARG_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Listen address can be specified as a literal address (IPv4 or\n"
    "IPv6), or a host name. Listen address \"*\" means listening on\n"
    "all available interfaces.\n\n"
    "Listen port can be specified as a literal port number, or a\n"
    "service name.\n\n"
    "By default \"*:1080\" is used.\n";

static void version(void)
{
    printf("%s version %s built on %s\n", PACKAGE_NAME, PACKAGE_VERSION, BUILD_TIMESTAMP);
}

static void usage(const char *bin_name)
{
    version();
    printf("\nUsage: %s [<option>...] [<listen-address>:<listen-port>]\n\n"
           "%s\n%s",
           bin_name, ARG_DESC, OPTIONS_DESC);
}

static int value2bool(const char *value)
{
    if (value == NULL)
        return 1;
    return (strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0 ||
            strcmp(value, "1") == 0) ? 1 : 0;
}

static int process_option(const char *bin_name, int opt, const char *arg, int in_file)
{
    switch (opt)
    {
    default:
    case '?': // Error in options
        return in_file ? -1 : 1;
    case -1: // <listen-address>:<listen-port>
        {
            size_t alen = strlen(arg), hlen;
            const char *sep;
            char *host = NULL;
            char *serv = NULL;

            if (alen == 0)
            {
                fprintf(stderr, "Empty listen address\n");
                return 1;
            }
            if (arg[0] == '[') // Literal IPv6 address
            {
                sep = strrchr(arg, ']');
                if (sep == NULL)
                {
                    fprintf(stderr, "Missing closing bracket: %s\n", arg);
                    return 1;
                }
                ++sep;
            }
            else
            {
                sep = strchr(arg, ':');
                if (sep == NULL)
                    sep = &arg[alen];
            }
            hlen = sep - arg;
            if (hlen > 0 && (hlen != 1 || arg[0] != '*'))
            {
                host = malloc(hlen + 1);
                if (host == NULL)
                {
                    fprintf(stderr, "Not enough memory for host: %s\n", arg);
                    return 1;
                }
                memcpy(host, arg, hlen);
                host[hlen] = '\0';
            }
            if (sep[0] == ':' && sep[1] != '\0')
            {
                serv = strdup(&sep[1]);
                if (serv == NULL)
                {
                    fprintf(stderr, "Not enough memory for service: %s\n", arg);
                    return 1;
                }
            }
            if (CONFIG.listen_host != NULL)
                free(CONFIG.listen_host);
            CONFIG.listen_host = host;
            if (CONFIG.listen_service != NULL)
                free(CONFIG.listen_service);
            CONFIG.listen_service = serv;
        }
        break;
    case 'c':  // --config=<config-file>
        if (in_file)
            return -1;
        {
            FILE *cfp = fopen(arg, "rt");
            char line[1024];
            int ret = 0;

            if (cfp == NULL)
            {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
                fprintf(stderr, "Cannot open config file '%s': %m\n", arg);
#pragma GCC diagnostic pop
                return 1;
            }
            while (ret == 0 && fgets(line, sizeof(line), cfp) != NULL)
            {
                char *sp, *ep;
                const struct option *o;

                for (sp = &line[strlen(line)];
                     sp > line && isspace(sp[-1]); sp--);
                *sp = '\0';
                for (sp = line; *sp != '\0' && isspace(*sp); sp++);
                if (*sp == '\0' || *sp == '#')
                    continue;
                if ((ep = strchr(sp, '=')) == NULL)
                {
                    fprintf(stderr, "Unseparated line '%s' in config file '%s'\n",
                        sp, arg);
                    ret = 1;
                    break;
                }
                *ep++ = '\0';
                if (strcmp(sp, "listen") == 0)
                    ret = process_option(bin_name, -1, ep, 1);
                else
                {
                    for (o = LONG_OPTS; o->name != NULL; o++)
                        if (strcmp(sp, o->name) == 0)
                        {
                            ret = process_option(bin_name, o->val, ep, 1);
                            break;
                        }
                    if (o->name == NULL || ret < 0)
                    {
                        fprintf(stderr, "Unrecognized option '%s' in config file '%s'\n",
                            sp, arg);
                        ret = 1;
                        break;
                    }
                }
            }
            fclose(cfp);
            if (ret != 0)
                return ret;
        }
        break;
    case 1000: // --nofork
        if (CONFIG.nofork < 0)
            break;
        if (in_file)
            CONFIG.nofork = value2bool(arg);
        else
            CONFIG.nofork = 1;
        break;
    case 'L': // --logmode=<mode>
        if ((CONFIG.logmode = logger_name2mode(arg)) < 0)
        {
            fprintf(stderr, "Unknown logging mode '%s'\n", arg);
            return 1;
        }
        if (logger_need_nofork(CONFIG.logmode))
            CONFIG.nofork = -1;
        break;
    case 'v': // --loglevel=<level>
        if ((CONFIG.loglevel = logger_name2level(arg)) < 0)
        {
            fprintf(stderr, "Unknown logging level '%s'\n", arg);
            return 1;
        }
        break;
    case 'a': // --auth=[<format>:]<secrets-file>
        authfile_parse(arg);
        break;
    case 'A': // --anonymous
        if (in_file)
            authuser_anon_allow(value2bool(arg));
        else
            authuser_anon_allow(1);
        break;
    case 'u': // --user=<uid>
        if ((CONFIG.drop_uid = util_parse_user(arg)) == (uid_t)-1)
        {
            fprintf(stderr, "Cannot find user '%s'\n", arg);
            return 1;
        }
        break;
    case 'g': // --group=<gid>
        if ((CONFIG.drop_gid = util_parse_group(arg)) == (gid_t)-1)
        {
            fprintf(stderr, "Cannot find group '%s'\n", arg);
            return 1;
        }
        break;
    case 'h': // --help
        if (in_file)
            return -1;
        usage(bin_name);
        return 2;
    case 'V': // --version
        if (in_file)
            return -1;
        version();
        return 2;
    }
    return 0;
}

volatile sig_atomic_t EXIT_SIGNO = 0; // Signal that resulted in an abort

static void signal_handler(int signo)
{
    int fd;

    EXIT_SIGNO = signo;
    for (fd = 3; fd < FD_SETSIZE; fd++)
        if (fcntl(fd, F_GETFL) != -1)
            close(fd);
}

int main(int argc, char **argv)
{
    int ret, opt, nfds;
    fd_set fds;
    struct sigaction sa = {
        .sa_flags   = 0,
        .sa_handler = signal_handler,
    };

    while ((opt = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1)
        if ((ret = process_option(argv[0], opt, optarg, 0)) != 0)
            exit(ret);
    if (optind < argc)
    {
        if ((optind + 1) < argc)
        {
            usage(argv[0]);
            exit(2);
        }
        if ((ret = process_option(argv[0], -1, argv[optind], 0)) != 0)
            exit(ret);
    }
    if (CONFIG.listen_service == NULL)
        CONFIG.listen_service = DEFAULT_LISTEN_SERVICE;

    logger_init(CONFIG.nofork, CONFIG.logmode, CONFIG.loglevel);
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    crypto_init();
    if ((nfds = socks_listen_at(CONFIG.listen_host, CONFIG.listen_service, &fds)) < 0)
        exit(1);
    if (CONFIG.nofork == 0)
        daemonize(CONFIG.drop_gid, CONFIG.drop_uid);
    logger(LOG_INFO, "Running %s version %s, built on %s", PACKAGE_NAME, PACKAGE_VERSION, BUILD_TIMESTAMP);
    socks_accept_loop(nfds, &fds);
    if (EXIT_SIGNO != 0)
        logger(LOG_ERR, "Received signal %d, exiting", EXIT_SIGNO);
    else
        logger(LOG_INFO, "Exiting");
    return 0;
}

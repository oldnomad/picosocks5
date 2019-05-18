#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "authfile.h"
#include "authuser.h"
#include "socks5.h"
#include "logger.h"
#include "util.h"
#include "inifile.h"
#include "cmdline.h"

#define FULL_VERSION_TEXT  PACKAGE_NAME " " PACKAGE_VERSION;

#define DEFAULT_LISTEN_SERVICE "1080"

static int process_include  (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_nofork   (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_logmode  (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_loglevel (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_authfile (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_anonymous(const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_listen   (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_bind     (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_user     (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_group    (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_help     (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);
static int process_version  (const ini_context_t *ctxt, const ini_option_t *opt, const char *value);

static const ini_option_t COMMON_SECTION[] = {
    { "include",   "config",    'c', INI_TYPE_PLAIN,   process_include   },
    { "nofork",    "nofork",      0, INI_TYPE_BOOLEAN, process_nofork    },
    { "logmode",   "logmode",   'L', INI_TYPE_PLAIN,   process_logmode   },
    { "loglevel",  "loglevel",  'v', INI_TYPE_PLAIN,   process_loglevel  },
    { "auth",      "auth",      'a', INI_TYPE_PLAIN,   process_authfile  },
    { "anonymous", "anonymous", 'A', INI_TYPE_BOOLEAN, process_anonymous },
    { "listen",    NULL,          1, INI_TYPE_PLAIN,   process_listen    },
    { "bind",      "bind",      'B', INI_TYPE_PLAIN,   process_bind      },
    { "user",      "user",      'u', INI_TYPE_PLAIN,   process_user      },
    { "group",     "group",     'g', INI_TYPE_PLAIN,   process_group     },
    { "=",         "help",      'h', INI_TYPE_BOOLEAN, process_help      },
    { "=",         "version",   'V', INI_TYPE_BOOLEAN, process_version   },
    { NULL }
};

static const char OPTIONS_DESC[] =
    //        1         2         3         4         5         7
    //23456789012345678901234567890123456789012345678901234567890123567890
    "Options:\n\n"
    "    -c <config-file>\n"
    "        Read options from specified configuration file.\n\n"
    "    -a [<format>:]<secrets-file>, --auth=[<format>:]<secrets-file>\n"
    "        Secrets file for authentication. If format is not\n"
    "        explicitly specified, \"password\" is implied.\n\n"
    "    -A, --anonymous\n"
    "        Allow anonymous access even if there is a non-anonymous\n"
    "        method available.\n\n"
    "    -B <address>, --bind <address>\n"
    "        Specify external address to use for BIND and UDP ASSOCIATE\n"
    "        commands. Note that only the last specified address for\n"
    "        each address family will be used. Default is no known\n"
    "        external addresses.\n\n"
    "    -u <user>, --user=<user>\n"
    "    -g <group>, --group=<group>\n"
    "        Specify non-privileged user and group to use for daemon\n"
    "        execution; both <user> and <group> can be specified either\n"
    "        as names, or as numeric values, decimal, octal, or\n"
    "        hexadecimal (in C notation).\n\n"
    "    --nofork\n"
    "        Do not fork the daemon to background.\n\n"
    "        Note that the daemon won't fork if its parent is init\n"
    "        process (PID 1).\n\n"
    "    -L <mode>, --logmode=<mode>\n"
    "        Specify logging mode. Supported modes are:\n"
    "            syslog   - log to syslog;\n"
    "            stderr   - log to stderr;\n"
    "            combined - log to both syslog and stderr.\n\n"
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

static const ini_option_t *section_callback(const ini_context_t *ctxt)
{
    if (ctxt->section != NULL)
        return NULL;
    return COMMON_SECTION;
}

static int value2bool(const char *value)
{
    if (value == NULL)
        return 1;
    return (strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0 ||
            strcmp(value, "1") == 0) ? 1 : 0;
}

static int process_include(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    (void)opt;
    return ini_load(value, section_callback, ctxt->context);
}

static int process_nofork (const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    if (cfg->nofork < 0)
        return 0;
    cfg->nofork = value2bool(value);
    return 0;
}

static int process_logmode(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    if ((cfg->logmode = logger_name2mode(value)) < 0)
    {
        ini_error(ctxt, "unknown logging mode '%s'", value);
        return -1;
    }
    if (logger_need_nofork(cfg->logmode))
        cfg->nofork = -1;
    return 0;
}

static int process_loglevel(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    if ((cfg->loglevel = logger_name2level(value)) < 0)
    {
        ini_error(ctxt, "unknown logging level '%s'", value);
        return -1;
    }
    return 0;
}

static int process_authfile(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    (void)ctxt;
    (void)opt;
    authfile_parse(value);
    return 0;
}

static int process_anonymous(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    (void)ctxt;
    (void)opt;
    authuser_anon_allow(value2bool(value));
    return 0;
}

static int process_listen(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;
    size_t alen, hlen;
    const char *sep;
    char *host = NULL;
    char *serv = NULL;

    (void)opt;
    if (value == NULL || *value == '\0')
    {
        ini_error(ctxt, "empty listen address");
        return -1;
    }
    alen = strlen(value);
    if (value[0] == '[') // Literal IPv6 address
    {
        sep = strrchr(value, ']');
        if (sep == NULL)
        {
            ini_error(ctxt, "missing closing bracket: %s", value);
            return -1;
        }
        ++sep;
    }
    else
    {
        sep = strchr(value, ':');
        if (sep == NULL)
            sep = &value[alen];
    }
    hlen = sep - value;
    if (hlen > 0 && (hlen != 1 || value[0] != '*'))
    {
        host = malloc(hlen + 1);
        if (host == NULL)
        {
            ini_error(ctxt, "not enough memory for host: %s", value);
            return -1;
        }
        memcpy(host, value, hlen);
        host[hlen] = '\0';
    }
    if (sep[0] == ':' && sep[1] != '\0')
    {
        serv = strdup(&sep[1]);
        if (serv == NULL)
        {
            ini_error(ctxt, "not enough memory for service: %s", value);
            return -1;
        }
    }
    if (cfg->listen_host != NULL)
        free(cfg->listen_host);
    cfg->listen_host = host;
    if (cfg->listen_service != NULL)
        free(cfg->listen_service);
    cfg->listen_service = serv;
    return 0;
}

static int process_bind(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    (void)ctxt;
    (void)opt;
    socks_set_bind_if(value);
    return 0;
}

static int process_user(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    if ((cfg->drop_uid = util_parse_user(value)) == (uid_t)-1)
    {
        ini_error(ctxt, "cannot find user '%s'", value);
        return -1;
    }
    return 0;
}

static int process_group(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    if ((cfg->drop_gid = util_parse_group(value)) == (gid_t)-1)
    {
        ini_error(ctxt, "cannot find group '%s'", value);
        return -1;
    }
    return 0;
}

static int process_help(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    daemon_config_t *cfg = ctxt->context;

    (void)opt;
    (void)value;
    printf("%s\n\n"
           "Usage: %s [<option>...] [<listen-address>:<listen-port>]\n\n"
           "%s\n%s",
           cmdline_version(), cfg->progname, ARG_DESC, OPTIONS_DESC);
    exit(0);
    return 0;
}

static int process_version(const ini_context_t *ctxt, const ini_option_t *opt, const char *value)
{
    (void)ctxt;
    (void)opt;
    (void)value;
    printf("%s\n", cmdline_version());
    exit(0);
    return 0;
}

const char *cmdline_version(void)
{
    return FULL_VERSION_TEXT;
}

void cmdline_process(int argc, char **argv, daemon_config_t *cfg)
{
    int ret;

    if ((ret = ini_args(argc, argv, section_callback, cfg)) != 0)
        exit(1);
    if (cfg->listen_service == NULL)
        cfg->listen_service = DEFAULT_LISTEN_SERVICE;
}

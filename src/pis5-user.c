#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include "auth.h"
#include "authfile.h"
#include "logger.h"
#include "crypto.h"
#include "util.h"
#include "socks5bits.h"

#define MAX_PASSWORD_LENGTH  1024 // Max password length (including newline)
#define MAX_SECRET_SIZE      4096 // Max secret data size

static const char SHORT_OPTS[] = "m:h";
static const struct option LONG_OPTS[] = {
    { "method",      1, NULL, 'm'  },
    { "help",        0, NULL, 'h'  },
    { NULL }
};

static void usage(const char *bin_name)
{
    //      0        1         2         3         4         5         6         7         8
    //      12345678901234567890123456789012345678901234567890123456789012345678901234567890
    printf("Usage: %s [<option>...] <user-name>\n\n"
           "Options:\n\n"
           "    -m <method-list>, --method <method-list>\n"
           "        Generate secrets only for specified methods. The option\n"
           "        accepts a comma-separated list of methods. Currently supported\n"
           "        methods are \"basic\" and \"chap\". Default is to use all known\n"
           "        methods.\n\n"
           "    -h, --help\n"
           "        Print usage message and exit.\n",
           bin_name);
    exit(2);
}

static int prompt_password(const char *prompt, char *buffer, size_t bufsize)
{
    struct termios oldtc, newtc;
    int notty = 0;
    const char *result;
    char *ep;

    fprintf(stderr, "%s: ", prompt);
    fflush(stderr);
    if (tcgetattr(0, &oldtc) != 0)
        notty = 1;
    else
    {
        newtc = oldtc;
        newtc.c_lflag &= ~ECHO;
        if (tcsetattr(0, TCSAFLUSH, &newtc) != 0)
            notty = 1;
    }
    errno = 0;
    result = fgets(buffer, bufsize, stdin);
    if (notty == 0)
    {
        int err = errno;
        tcsetattr(0, TCSAFLUSH, &oldtc);
        fprintf(stderr, "\n");
        fflush(stderr);
        errno = err;
    }
    if (result == NULL)
        return -1;
    for (ep = &buffer[strlen(buffer)];
         ep > buffer && (ep[-1] == '\r' || ep[-1] == '\n'); ep--);
    *ep = '\0';
    return 0;
}

static int ask_password(char *buffer, size_t bufsize)
{
    char *buffer2;
    int result;

    if ((buffer2 = malloc(bufsize)) == NULL)
    {
        logger(LOG_ERR, "Not enough memory");
        return -1;
    }
    if (prompt_password("Enter password", buffer, bufsize) < 0 ||
        prompt_password("Enter password (again)", buffer2, bufsize) < 0)
    {
        logger(LOG_ERR, "Error reading password: %m");
        result = -1;
    }
    else if (strcmp(buffer, buffer2) != 0)
    {
        logger(LOG_ERR, "Passwords mismatch");
        result = -1;
    }
    else
        result = 0;
    free(buffer2);
    return result;
}

int main(int argc, char **argv)
{
    int opt;
    unsigned char methods[256/8];
    const char *username;
    char password[MAX_PASSWORD_LENGTH], secret[MAX_SECRET_SIZE];
    ssize_t seclen;
    const auth_method_t *m;

    memset(methods, 0xFF, sizeof(methods));
    while ((opt = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1)
    {
        switch (opt)
        {
        case '?': // Error in options
            return 1;
        case 'm': // --method=<method-list>
            memset(methods, 0x00, sizeof(methods));
            {
                char *sp, *ep;
                for (sp = optarg; sp != NULL; sp = ep)
                {
                    if ((ep = strchr(sp, ',')) != NULL)
                        *ep++ = '\0';
                    if ((m = auth_find_method(sp)) == NULL)
                    {
                        fprintf(stderr, "Unknown method \"%s\"\n", sp);
                        return 1;
                    }
                    methods[m->method / 8] |= 1u << (m->method % 8);
                }
            }
            break;
        case 'h': // --help
            usage(argv[0]);
            break;
        }
    }
    if (optind >= argc)
        usage(argv[0]);
    username = argv[optind];
    if ((optind + 1) < argc)
        usage(argv[0]);
    logger_init(1, 0, LOG_WARNING);
    if (ask_password(password, sizeof(password)) < 0)
        return 1;
    srand(time(NULL));
    crypto_init();
    for (m = auth_all_methods(); m->method != SOCKS_AUTH_INVALID; m++)
    {
        if (m->name == NULL || m->generator == NULL)
            continue;
        if ((methods[m->method / 8] & (1u << (m->method % 8))) == 0)
            continue;
        if ((seclen = m->generator(password, (unsigned char *)secret, sizeof(secret))) < 0)
            continue;
        printf("%s:%s:%.*s\n", username, m->name, (int)seclen, secret);
    }
    return 0;
}

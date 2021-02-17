/**
 * @file
 * Utility to create passwords for PicoSOCKS5.
 */
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
#include <crypt.h>
#include "logger.h"
#include "crypto.h"
#include "util.h"

#define MAX_PASSWORD_LENGTH  1024 ///< Max password length (including newline).
#define MAX_SECRET_SIZE      4096 ///< Max secret data size.

#define DEFAULT_SALT_SIZE   8     ///< Number of salt characters to generate for crypt(3)
#define DEFAULT_SALT_PREFIX "$6$" ///< Default crypt(3) method

static const char SHORT_OPTS[] = "m:h"; ///< Command-line short options.
/// Command-line long options.
static const struct option LONG_OPTS[] = {
    { "method",      1, NULL, 'm'  },
    { "help",        0, NULL, 'h'  },
    { NULL }
};

/**
 * Function type for password encoding method.
 *
 * @param password password to encode.
 * @param buffer   buffer for encoded password.
 * @param bufsize  size of buffer.
 * @return size of encoded password, or -1 on error.
 */
typedef ssize_t (*pwd_encode_t)(const char *password, char *buffer, size_t bufsize);

static ssize_t encode_crypt (const char *password, char *buffer, size_t bufsize);
static ssize_t encode_base64(const char *password, char *buffer, size_t bufsize);

/// Password encoding method.
struct pwd_encoding {
    const char  *name;   ///< Encoding method name.
    pwd_encode_t encode; ///< Encoding function.
};

/// List of supported encoding methods.
static const struct pwd_encoding METHODS[] = {
    { "basic", encode_crypt  },
    { "chap",  encode_base64 },
    { NULL,    NULL          }
};

/**
 * Print usage note and exit.
 *
 * @param bin_name name of this command.
 */
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

/**
 * Prompt for password and read it.
 *
 * @param prompt  prompt text.
 * @param buffer  buffer for password.
 * @param bufsize size of buffer.
 * @return zero on success, or -1 on error.
 */
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

/**
 * Ask for password twice and compare.
 *
 * @param buffer  buffer for password.
 * @param bufsize buffer size.
 * @return zero on success, or -1 on error.
 */
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

/**
 * Password encoding with crypt(3).
 * @copydetails pwd_encode_t
 */
static ssize_t encode_crypt (const char *password, char *buffer, size_t bufsize) {
    // Salt alphabet contains 64 symbols, 6 bits per character;
    // 4 characters contain 3 bytes (24 bits) of randomness
    static const char ALPHABET[] = "ABCDEFGHIJKLMNOP"
                                   "QRSTUVWXYZabcdef"
                                   "ghijklmnopqrstuv"
                                   "wxyz0123456789/.";
    struct crypt_data cdata;
    char salt[sizeof(DEFAULT_SALT_PREFIX) + DEFAULT_SALT_SIZE + 1], *ep;
    const char *cpass;
    unsigned char randval[(DEFAULT_SALT_SIZE*3 + 2)/4];
    unsigned rval = 0;
    size_t csize;
    int i, j;

    memcpy(salt, DEFAULT_SALT_PREFIX, sizeof(DEFAULT_SALT_PREFIX) - 1);
    ep = &salt[sizeof(DEFAULT_SALT_PREFIX) - 1];
    crypto_generate_nonce(randval, sizeof(randval));
    rval = 0;
    for (i = 0, j = 0; i < DEFAULT_SALT_SIZE; i++)
    {
        switch (i % 4)
        {
        case 0:
            rval = randval[j++];
            break;
        case 1:
            rval = rval|(((unsigned)randval[j++]) << 2);
            break;
        case 2:
            rval = rval|(((unsigned)randval[j++]) << 4);
            break;
        case 3:
            break;
        }
        *ep++ = ALPHABET[rval & 0x3F];
        rval >>= 6;
    }
    *ep++ = '$';
    *ep = '\0';
    cpass = crypt_r(password, salt, &cdata);
    if (cpass == NULL)
    {
        logger(LOG_ERR, "Encryption error: %m");
        return -1;
    }
    csize = strlen(cpass);
    if (bufsize < csize)
    {
        logger(LOG_ERR, "Encrypted password is too long");
        return -1;
    }
    memcpy(buffer, cpass, csize);
    return csize;
}

/**
 * Password encoding with Base64.
 * @copydetails pwd_encode_t
 */
static ssize_t encode_base64(const char *password, char *buffer, size_t bufsize) {
    ssize_t seclen;

    if (bufsize <= BASE64_PREFIX_LEN)
        goto TOO_LONG;
    memcpy(buffer, BASE64_PREFIX, BASE64_PREFIX_LEN);
    buffer  += BASE64_PREFIX_LEN;
    bufsize -= BASE64_PREFIX_LEN;
    if ((seclen = util_base64_encode(password, strlen(password), buffer, bufsize)) < 0)
    {
TOO_LONG:
        logger(LOG_ERR, "Encoded password is too long");
        return -1;
    }
    return seclen + BASE64_PREFIX_LEN;
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
    int opt;
    // NOTE: We rely on number of encodings being <= 32
    unsigned long methods, mask;
    const char *username;
    char password[MAX_PASSWORD_LENGTH], secret[MAX_SECRET_SIZE];
    ssize_t seclen;
    const struct pwd_encoding *enc;

    methods = 0;
    while ((opt = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1)
    {
        switch (opt)
        {
        case '?': // Error in options
            return 1;
        case 'm': // --method=<method-list>
            {
                char *sp, *ep;
                for (sp = optarg; sp != NULL; sp = ep)
                {
                    if ((ep = strchr(sp, ',')) != NULL)
                        *ep++ = '\0';
                    for (enc = METHODS, mask = 1; enc->name != NULL; enc++, mask <<= 1)
                        if (strcmp(enc->name, sp) == 0) {
                            methods |= mask;
                            break;
                        }
                    if (enc->name == NULL)
                    {
                        fprintf(stderr, "Unknown method \"%s\"\n", sp);
                        return 1;
                    }
                }
            }
            break;
        case 'h': // --help
            usage(argv[0]);
            break;
        }
    }
    if (methods == 0)
        methods = 0xFFFFFFFFUL;
    if (optind >= argc)
        usage(argv[0]);
    username = argv[optind];
    if ((optind + 1) < argc)
        usage(argv[0]);
    logger_init(1, 0, LOG_WARNING);
    if (ask_password(password, sizeof(password)) < 0)
        return 1;
    crypto_init();
    for (enc = METHODS, mask = 1; enc->name != NULL; enc++, mask <<= 1)
    {
        if ((methods & mask) == 0)
            continue;
        if ((seclen = enc->encode(password, secret, sizeof(secret))) < 0)
            continue;
        printf("%s:%s:%.*s\n", username, enc->name, (int)seclen, secret);
    }
    return 0;
}

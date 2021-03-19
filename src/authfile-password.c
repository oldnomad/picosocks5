/**
 * @file
 * Simple password file format.
 *
 * Password file is a text file with lines containing colon-separated
 * username, group name, and secret. Secret can be either a crypt(3)
 * password hash, or a Base64-encoded password with prefix "$base64$".
 *
 * Password file is only read once, and all its data is kept in memory.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include "auth.h"
#include "authfile.h"
#include "crypto.h"
#include "socks5bits.h"
#include "util.h"

#define MAX_LINE_LENGTH 1024 ///< Maximum line length.

/**
 * Supported secret types.
 */
enum pwd_type {
    PWDTYPE_PLAIN = 0, ///< Plain (unencrypted) password.
    PWDTYPE_CRYPT,     ///< Password hash using crypt(3).
};

/**
 * User/secret definition.
 */
struct auth_user {
    struct auth_user *next;      ///< Pointer to the next element.
    enum pwd_type     type;      ///< Secret type.
    const char       *user;      ///< User name, or NULL for server auth.
    const char       *group;     ///< Group name, or NULL.
    const void       *secret;    ///< Secret data.
    size_t            secretlen; ///< Length of secret
};

/**
 * Password file parser.
 * @copydetails authfile_parser_t
 */
void *authpwd_parse(const char *filespec)
{
    FILE *f;
    char line[MAX_LINE_LENGTH], decbuf[MAX_LINE_LENGTH*3/4];
    struct auth_user *list[2] = { NULL, NULL };

    f = fopen(filespec, "rt");
    if (f == NULL)
    {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
        fprintf(stderr, "Cannot open auth file '%s': %m\n", filespec);
#pragma GCC diagnostic pop
        exit(1);
    }
    while (fgets(line, sizeof(line), f) != NULL)
    {
        char *sp, *pp, *secp, *grpp;
        size_t ulen, glen, seclen, blen;
        enum pwd_type type;
        struct auth_user *u;

        for (sp = &line[strlen(line)];
             sp > line && (sp[-1] == '\n' || sp[-1] == '\r'); sp--);
        *sp = '\0';
        if ((sp = strchr(line, ':')) == NULL)
        {
            fprintf(stderr, "Unseparated line '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
        *sp++ = '\0';
        ulen = sp - line;
        if ((pp = strchr(sp, ':')) == NULL)
        {
            fprintf(stderr, "User '%s' in file '%s' is in old format, fixed\n",
                line, filespec);
            pp = sp;
            sp = NULL;
            glen = 0;
        }
        else
        {
            *pp++ = '\0';
            glen = pp - sp;
        }
        grpp = sp;
        if (strncmp(pp, BASE64_PREFIX, BASE64_PREFIX_LEN) == 0)
        {
            ssize_t len = util_base64_decode(pp + BASE64_PREFIX_LEN, decbuf, sizeof(decbuf));
            if (len < 0)
            {
                fprintf(stderr, "Invalid Base64 encoding for user '%s' in auth file '%s'\n",
                    line, filespec);
                exit(1);
            }
            secp = decbuf;
            seclen = len;
            type = PWDTYPE_PLAIN;
        }
        else
        {
            secp = pp;
            seclen = strlen(secp) + 1;
            type = PWDTYPE_CRYPT;
        }
        blen = sizeof(*u) + ulen + glen + seclen;
        if ((u = malloc(blen)) == NULL)
        {
            fprintf(stderr, "Not enough memory to add username '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
        sp = (char *)&u[1];
        u->next = NULL;
        u->type = type;
        if (ulen > 1)
        {
            u->user = sp;
            memcpy(sp, line, ulen);
            sp += ulen;
        }
        else
            u->user = NULL;
        if (glen > 1 && grpp != NULL)
        {
            u->group = sp;
            memcpy(sp, grpp, glen);
            sp += glen;
        }
        else
            u->group = NULL;
        u->secret = sp;
        memcpy(sp, secp, seclen);
        u->secretlen = seclen;
        if (list[1] != NULL)
            list[1]->next = u;
        else
            list[0] = u;
        list[1] = u;
    }
    fclose(f);
    return list[0];
}

/**
 * Password file authentication callback.
 * @copydetails authfile_callback_t
 */
ssize_t authpwd_callback(void *handle, authfile_method_t method, const char *user,
                         const unsigned char *input, size_t inplen,
                         unsigned char *buffer, size_t bufsize)
{
    const struct auth_user *list = handle;
    const struct auth_user *u;
    unsigned char hash[CRYPTO_MD5_SIZE];

    switch (method)
    {
    case AUTHFILE_CHECK:
        if (user == NULL)
            return 0;
        for (u = list; u != NULL; u = u->next)
            if (u->user != NULL && strcmp(u->user, user) == 0)
            {
                if (buffer != NULL && bufsize > 0)
                {
                    if (u->group != NULL && bufsize > 1)
                    {
                        size_t glen = strlen(u->group);
                        if (glen >= bufsize)
                            glen = bufsize - 1;
                        memcpy(buffer, u->group, glen);
                        buffer[glen] = '\0';
                    }
                    else
                        buffer[0] = '\0';
                }
                return 0;
            }
        return -1;
    case AUTHFILE_LOGIN:
        if (user == NULL)
            return list != NULL ? 0 : -1;
        for (u = list; u != NULL; u = u->next)
        {
            if (u->user == NULL || strcmp(u->user, user) != 0)
                continue;
            switch (u->type)
            {
            case PWDTYPE_PLAIN:
                if (u->secretlen == inplen &&
                    memcmp(u->secret, input, inplen) == 0)
                    return 0;
                break;
            case PWDTYPE_CRYPT:
                if (inplen >= MAX_PASSWORD_LENGTH)
                    return -1;
                {
                    char pass[MAX_PASSWORD_LENGTH];
                    struct crypt_data cdata;
                    const char *cpass;

                    memcpy(pass, input, inplen);
                    pass[inplen] = '\0';
                    cpass = crypt_r(pass, u->secret, &cdata);
                    if (cpass != NULL && strcmp(cpass, u->secret) == 0)
                        return 0;
                }
                break;
            }
        }
        return -1;
    case AUTHFILE_HMAC_MD5_CHALLENGE:
        if (user == NULL)
        {
            for (u = list; u != NULL; u = u->next)
                if (u->user != NULL && u->type == PWDTYPE_PLAIN)
                    return 0;
            return -1;
        }
        if (buffer == NULL || bufsize == 0)
            return -1;
        for (u = list; u != NULL; u = u->next)
            if (u->user != NULL && strcmp(u->user, user) == 0 && u->type == PWDTYPE_PLAIN)
                break;
        if (u == NULL)
            return -1;
        crypto_generate_nonce(buffer, bufsize);
        return bufsize;
    case AUTHFILE_HMAC_MD5_RESPONSE:
        if (user == NULL)
        {
            for (u = list; u != NULL; u = u->next)
                if (u->user != NULL && u->type == PWDTYPE_PLAIN)
                    return 0;
            return -1;
        }
        if (input  == NULL || inplen  != CRYPTO_MD5_SIZE ||
            buffer == NULL || bufsize == 0)
            return -1;
        for (u = list; u != NULL; u = u->next)
        {
            if (u->user == NULL || strcmp(u->user, user) != 0 || u->type != PWDTYPE_PLAIN)
                continue;
            if (crypto_hmac_md5(u->secret, u->secretlen,
                                buffer, bufsize,
                                hash, CRYPTO_MD5_SIZE) != 0)
                return -1;
            if (memcmp(input, hash, CRYPTO_MD5_SIZE) == 0)
                return 0;
        }
        return -1;
    case AUTHFILE_HMAC_MD5_SERVER:
        if (user == NULL)
        {
            for (u = list; u != NULL; u = u->next)
                if (u->user == NULL && u->type == PWDTYPE_PLAIN)
                    return 0;
            return -1;
        }
        if (input  == NULL || inplen == 0 ||
            buffer == NULL || bufsize < CRYPTO_MD5_SIZE)
            return -1;
        for (u = list; u != NULL; u = u->next)
            if (u->user == NULL && u->type == PWDTYPE_PLAIN)
                break;
        if (u == NULL)
            return -1;
        if (crypto_hmac_md5(u->secret, u->secretlen,
                            input, inplen,
                            buffer, CRYPTO_MD5_SIZE) != 0)
            return -1;
        return CRYPTO_MD5_SIZE;
    }
    return -1;
}

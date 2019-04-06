#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"
#include "authuser.h"
#include "authfile.h"
#include "socks5bits.h"
#include "util.h"

#define MAX_LINE_LENGTH 1024 // Maximum line length

static const char BASE64_PREFIX[] = "$base64$";

/**
 * AUTH FILE FORMAT: Text file with lines containing colon-separated
 * username, auth method name, and method-dependent secret.
 */
void authfile_format_password(const char *filespec)
{
    FILE *f = fopen(filespec, "rt");
    char line[MAX_LINE_LENGTH], decbuf[MAX_LINE_LENGTH*3/4];

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
        char *sp, *pp, *secp;
        size_t seclen;
        const auth_method_t *m;

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
        if ((pp = strchr(sp, ':')) == NULL)
        {
            fprintf(stderr, "User '%s' in file '%s' is in old format, fixed\n",
                line, filespec);
            sp = NULL;
            pp = sp;
        }
        else
            *pp++ = '\0';
        m = auth_find_method(sp);
        if (m == NULL)
            continue;
        if (strncmp(pp, BASE64_PREFIX, sizeof(BASE64_PREFIX) - 1) == 0)
        {
            ssize_t len = util_base64_decode(pp + sizeof(BASE64_PREFIX) - 1, decbuf, sizeof(decbuf));
            if (len < 0)
            {
                fprintf(stderr, "Invalid Base64 encoding for user '%s' in auth file '%s'\n",
                    line, filespec);
                exit(1);
            }
            secp = decbuf;
            seclen = len;
        }
        else
        {
            secp = pp;
            seclen = strlen(secp) + 1;
        }
        if (authuser_append(m->method, line, secp, seclen) != 0)
        {
            fprintf(stderr, "Failed to add username '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
    }
    fclose(f);
}

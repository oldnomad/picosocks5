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

/**
 * AUTH FILE FORMAT: Text file with lines containing colon-separated
 * username and password hash (crypt(3)-compatible salted)
 */
void authfile_format_password(const char *filespec)
{
    FILE *f = fopen(filespec, "rt");
    char line[1024];

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
        char *sp;
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
        if (authuser_append(SOCKS_AUTH_BASIC, line, sp, strlen(sp) + 1) != 0)
        {
            fprintf(stderr, "Failed to add username '%s' in auth file '%s'\n",
                line, filespec);
            exit(1);
        }
    }
    fclose(f);
}

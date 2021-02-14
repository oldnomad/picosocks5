/**
 * @file
 * Functions for parsing command line arguments and INI file.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "inifile.h"

#define MAX_LINE_LENGTH 1024 ///< Maximum line length.

/**
 * Skip leading whitespace.
 *
 * @param text pointer to text.
 * @return pointer to first non-whitespace character.
 */
static char *skip_space(char *text)
{
    char *s;

    for (s = text; isspace(*s); s++);
    return s;
}

/**
 * Skip trailing whitespace.
 *
 * @param text   pointer to text.
 * @param offset offset in text.
 * @return pointer to the first whitespace before the offset.
 */
static char *last_space(char *text, size_t offset)
{
    char *s;

    for (s = &text[offset]; s > text && isspace(s[-1]); s--);
    return s;
}

/**
 * Find option by parameter name.
 *
 * @param optlist option list.
 * @param param   parameter name.
 * @return option descriptor, or NULL if not found.
 */
static const ini_option_t *findopt_by_name(const ini_option_t *optlist, const char *param)
{
    const ini_option_t *opt;

    for (opt = optlist; opt->name != NULL; opt++)
        if (strcmp(opt->name, param) == 0)
            return opt;
    return NULL;
}

/**
 * Find option by option character.
 *
 * @param optlist option list.
 * @param optchar option character.
 * @return option descriptor, or NULL if not found.
 */
static const ini_option_t *findopt_by_optchar(const ini_option_t *optlist, char optchar)
{
    const ini_option_t *opt;

    for (opt = optlist; opt->name != NULL; opt++)
        if (opt->optchar == optchar)
            return opt;
    return NULL;
}

/**
 * Report error in INI-file or command line parsing.
 *
 * @param ctxt option parsing context.
 * @param fmt  message format.
 * @param ...  message parameters.
 */
__attribute__(( __format__(__printf__, 2, 3) ))
void ini_error(const ini_context_t *ctxt, const char *fmt, ...)
{
    va_list args;

    if (ctxt->filename == NULL)
        fprintf(stderr, "CMD: ");
    else
        fprintf(stderr, "[%s:%d] ", ctxt->filename, ctxt->lineno);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

/**
 * Load and parse INI-file.
 *
 * @param filename path to INI file.
 * @param callback section callback.
 * @param context  callback context.
 * @return zero on success, or -1 on error.
 */
int ini_load(const char *filename, ini_section_cbk_t callback, void *context)
{
    ini_context_t ctxt = {
        .filename = filename,
        .lineno   = 0,
        .section  = NULL,
        .context  = context
    };
    const ini_option_t *optlist = NULL, *opt;
    FILE *cfp;
    char line[MAX_LINE_LENGTH + 1];
    int ret = 0;

    if ((optlist = callback(&ctxt)) == NULL)
    {
        ini_error(&ctxt, "internal config file processing error");
        return -1;
    }
    if ((cfp = fopen(filename, "rt")) == NULL)
    {
        ini_error(&ctxt, "cannot open config file: %m");
        return -1;
    }
    while (fgets(line, sizeof(line), cfp) != NULL)
    {
        char *sp, *ep, *sep;

        ctxt.lineno++;
        sp = skip_space(line);
        if (*sp == '\0' || *sp == ';' || *sp == '#')
            continue;
        if (*sp == '[')
        {
            ep = last_space(sp, strlen(sp));
            // ASSERT: ep > sp, since !isspace('[')
            *ep-- = '\0';
            if (*ep != ']')
            {
                ini_error(&ctxt, "malformed section name '%s'", sp);
                ret = -1;
                break;
            }
            // ASSERT: ep > sp, since !isspace(']')
            *ep = '\0';
            ++sp;
            if (sp >= ep)
            {
                ini_error(&ctxt, "malformed section name '[]'");
                ret = -1;
                break;
            }
            if (ctxt.section != NULL)
                free(ctxt.section);
            if ((ctxt.section = strdup(sp)) == NULL)
            {
                ini_error(&ctxt, "not enough memory for section name '%s'", sp);
                ret = -1;
                break;
            }
            if ((optlist = callback(&ctxt)) == NULL)
            {
                ini_error(&ctxt, "unrecognized section '%s'", ctxt.section);
                ret = -1;
                break;
            }
            continue;
        }
        if ((sep = strchr(sp, '=')) == NULL)
        {
            ini_error(&ctxt, "unseparated line");
            ret = -1;
            break;
        }
        ep = last_space(sp, sep - sp);
        *ep = '\0';
        if ((opt = findopt_by_name(optlist, sp)) == NULL)
        {
            ini_error(&ctxt, "unrecognized parameter '%s'", sp);
            ret = -1;
            break;
        }

        if (opt->type == INI_TYPE_LIST)
        {
            char *comma;

            for (comma = sep; comma != NULL; )
            {
                sp = skip_space(&comma[1]);
                comma = strchr(sp, ',');
                if (comma == NULL)
                    ep = last_space(sp, strlen(sp));
                else
                    ep = last_space(sp, comma - sp);
                *ep = '\0';
                if (opt->callback(&ctxt, opt, sp) != 0)
                {
                    ret = -1;
                    break;
                }
            }
            if (ret < 0)
                break;
        }
        else
        {
            sp = skip_space(&sep[1]);
            ep = last_space(sp, strlen(sp));
            *ep = '\0';
            if (opt->callback(&ctxt, opt, sp) != 0)
            {
                ret = -1;
                break;
            }
        }
    }
    if (ctxt.section != NULL)
        free(ctxt.section);
    fclose(cfp);
    return ret;
}

/**
 * Load and parse command-line arguments.
 *
 * @param argc     number of command line parameters.
 * @param argv     array of command line parameters.
 * @param callback section callback.
 * @param context  callback context.
 * @return zero on success, or -1 on error.
 */
int ini_args(int argc, char **argv, ini_section_cbk_t callback, void *context)
{
    ini_context_t ctxt = {
        .filename = NULL,
        .lineno   = 0,
        .section  = NULL,
        .context  = context
    };
    const ini_option_t *optlist = NULL, *opt;
    char *sopts, *optarea = NULL, *pp, *sp, *ep;
    struct option *lopts, *lp;
    size_t slen, llen;
    int ret = 0, val, idx;

    if ((optlist = callback(&ctxt)) == NULL)
    {
        ini_error(&ctxt, "internal command line processing error");
        return -1;
    }
    slen = 3; // Initial "-:" and terminal NUL
    llen = 1; // End-of-list structure
    for (opt = optlist; opt->name != NULL; opt++)
    {
        if (opt->optname != NULL)
            llen++;
        if (opt->optchar != '\0')
        {
            slen++;
            if (opt->type != INI_TYPE_BOOLEAN)
                slen++;
        }
    }
    if ((optarea = malloc(llen*sizeof(struct option) + slen)) == NULL)
    {
        ini_error(&ctxt, "not enough memory for command line processing");
        ret = -1;
        goto ON_ERROR;
    }
    lp = lopts = (void *)optarea;
    pp = sopts = (void *)&lopts[llen];
    *pp++ = '-';
    *pp++ = ':';
    for (opt = optlist, val = 256; opt->name != NULL; opt++, val++)
    {
        if (opt->optname != NULL)
        {
            lp->name    = opt->optname;
            lp->has_arg = (opt->type == INI_TYPE_BOOLEAN) ? 0 : 1;
            lp->flag    = NULL;
            lp->val     = val;
            lp++;
        }
        if (opt->optchar != '\0')
        {
            *pp++ = opt->optchar;
            if (opt->type != INI_TYPE_BOOLEAN)
                *pp++ = ':';
        }
    }
    memset(lp, 0, sizeof(*lp));
    *pp = '\0';

    optind = 0; // GNU extension, see man getopt_long(3)
    opterr = 0;
    while ((val = getopt_long(argc, argv, sopts, lopts, NULL)) != -1)
    {
        if (val == '?')
        {
            ini_error(&ctxt, "unrecognized command line option: %s", argv[optind - 1]);
            ret = -1;
            goto ON_ERROR;
        }
        if (val == ':')
        {
            ini_error(&ctxt, "command line option missing value: %s", argv[optind - 1]);
            ret = -1;
            goto ON_ERROR;
        }
        if (val < 256)
            opt = findopt_by_optchar(optlist, val);
        else
            opt = &optlist[val - 256];
        switch (opt->type)
        {
        case INI_TYPE_BOOLEAN:
            if (opt->callback(&ctxt, opt, NULL) != 0)
            {
                ret = -1;
                goto ON_ERROR;
            }
            break;
        case INI_TYPE_LIST:
            // NOTE: We use the fact that 'optarg' points to an element of 'argv',
            //       so it's OK to modify it.
            for (ep = sp = optarg; ep != NULL; sp = ep)
            {
                // Unlike INI-file parameters, we don't skip whitespace here
                ep = strchr(sp, ',');
                if (ep != NULL)
                    *ep++ = '\0';
                if (opt->callback(&ctxt, opt, sp) != 0)
                {
                    ret = -1;
                    goto ON_ERROR;
                }
            }
            break;
        default:
            if (opt->callback(&ctxt, opt, optarg) != 0)
            {
                ret = -1;
                goto ON_ERROR;
            }
            break;
        }
    }
    opt = findopt_by_optchar(optlist, 1);
    for (idx = optind; idx < argc; idx++)
        if (opt->callback(&ctxt, opt, argv[idx]) != 0)
        {
            ret = -1;
            goto ON_ERROR;
        }
ON_ERROR:
    if (optarea != NULL)
        free(optarea);
    return ret;
}

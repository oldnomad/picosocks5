/**
 * @file
 * Authentication source functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "authfile.h"
#include "logger.h"

/**
 * List of supported file formats
 */
static const authfile_format_t FILE_FORMATS[] = {
    { "password", authpwd_parse, authpwd_callback },
    { NULL }
};

/**
 * Holder for parsed source.
 */
struct authfile_container {
    struct authfile_container *next;   ///< Pointer to the next element.
    const authfile_format_t   *format; ///< Source format.
    void                      *handle; ///< Opaque source handle.
};

/// List of parsed sources.
static struct authfile_container *AUTHFILE_SOURCES[2] = { NULL, NULL };
/// Flag allowing anonymous login
static int AUTHFILE_ANONYMOUS = 1;

/**
 * Manage anonymous allow flag.
 *
 * @param flag if not negative, new value for anonymous allow flag.
 * @return true if anonymous logins are allowed.
 */
int authfile_anonymous(int flag)
{
    if (flag >= 0)
        AUTHFILE_ANONYMOUS = flag;
    return AUTHFILE_SOURCES[0] == NULL || AUTHFILE_ANONYMOUS;
}

/**
 * Check whether authentication method is supported by any source.
 *
 * @param method authentication method.
 * @return true if the method is supported.
 */
int authfile_supported(authfile_method_t method)
{
    const struct authfile_container *c;

    for (c = AUTHFILE_SOURCES[0]; c != NULL; c = c->next)
        if (c->format->callback(c->handle, method, NULL, NULL, 0, NULL, 0) == 0)
            return 1;
    return 0;
}

/**
 * Parse authentication source.
 * This function detects prefix and passes the filespec tail to corresponding format parser.
 *
 * @param filespec authentication source with (optional) prefix.
 */
void authfile_parse(const char *filespec)
{
    const authfile_format_t *format;
    size_t fslen = strlen(filespec);
    const char *fs = filespec;
    struct authfile_container *c;

    for (format = FILE_FORMATS; format->prefix != NULL; format++)
    {
        size_t plen = strlen(format->prefix);
        if (plen < fslen && filespec[plen] == ':' &&
            memcmp(format->prefix, filespec, plen) == 0)
        {
            fs = &filespec[plen + 1];
            break;
        }
    }
    if (format->prefix == NULL)
        format = &FILE_FORMATS[0];
    if ((c = malloc(sizeof(*c))) == NULL)
    {
        fprintf(stderr, "Cannot allocate memory for authentication file '%s'\n", filespec);
        exit(1);
    }
    c->next   = NULL;
    c->format = format;
    c->handle = format->parse(fs);
    if (AUTHFILE_SOURCES[1] != NULL)
        AUTHFILE_SOURCES[1]->next = c;
    else
        AUTHFILE_SOURCES[0] = c;
    AUTHFILE_SOURCES[1] = c;
}

/**
 * Find authentication source for user, supporting specified method.
 *
 * @param user   user name.
 * @param method method to support.
 * @return opaque authentication source, or NULL if not found.
 */
const void *authfile_find_user(const char *user, authfile_method_t method)
{
    const struct authfile_container *c;

    if (user == NULL)
        return NULL;
    for (c = AUTHFILE_SOURCES[0]; c != NULL; c = c->next)
        if (c->format->callback(c->handle, AUTHFILE_CHECK, user, NULL, 0, NULL, 0) == 0 &&
            (method == AUTHFILE_CHECK || c->format->callback(c->handle, method, NULL, NULL, 0, NULL, 0) == 0))
            return c;
    return NULL;
}

/**
 * Call authentication callback.
 *
 * @param source  opaque authentication source.
 * @param method  authentication method.
 * @param user    user name, or NULL for support check.
 * @param input   input data, or NULL.
 * @param inplen  length of input data.
 * @param buffer  buffer for output data, or NULL.
 * @param bufsize buffer size.
 * @return length of output data or zero on success, or -1 on error.
 */
ssize_t authfile_callback(const void *source, authfile_method_t method, const char *user,
                          const unsigned char *input, size_t inplen,
                          unsigned char *buffer, size_t bufsize)
{
    const struct authfile_container *c = (const struct authfile_container *)source;

    if (c == NULL)
        return -1;
    return c->format->callback(c->handle, method, user, input, inplen, buffer, bufsize);
}

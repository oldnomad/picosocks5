/**
 * @file
 * Authentication source functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include "authfile.h"

/**
 * List of supported file formats
 */
static const authfile_format_t FILE_FORMATS[] = {
    { "password", authfile_format_password },
    { NULL,       authfile_format_password }
};

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
    format->parse(fs);
}

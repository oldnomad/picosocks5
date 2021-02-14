/**
 * @file
 * Definitions for authentication source formats.
 *
 * TO ADD A NEW AUTH FILE FORMAT:
 *
 * - Declare below a parse function with signature fitting authfile_parser_t.
 * - Go to authfile.c and insert an element into AUTHFILE_FORMATS[] array.
 */

/**
 * Function type for authentication source parser.
 *
 * @param filespec authentication source specification.
 */
typedef void (*authfile_parser_t)(const char *filespec);

/**
 * Authentication source format.
 */
typedef struct {
    const char *prefix;      ///< Format prefix
    authfile_parser_t parse; ///< Format parser function
} authfile_format_t;

void authfile_parse(const char *filespec);

// Specific parsers follow here
void authfile_format_password(const char *filespec);

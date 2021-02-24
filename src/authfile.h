/**
 * @file
 * Definitions for authentication source formats.
 *
 * TO ADD A NEW AUTH FILE FORMAT:
 *
 * - Declare below a parse function with signature fitting authfile_parser_t.
 * - Declare below an authentication callback with signatore fitting authfile_callback_t.
 * - Go to authfile.c and insert an element into AUTHFILE_FORMATS[] array.
 *
 * Authentication callback must support at least user check (AUTHFILE_CHECK).
 */

/**
 * Authentication callback methods that may be used.
 */
typedef enum {
    AUTHFILE_CHECK = 0,          ///< User check: no input, no output.
    AUTHFILE_LOGIN,              ///< Plain login: input password, no output.
    AUTHFILE_HMAC_MD5_CHALLENGE, ///< HMAC-MD5 challenge: no input, output challenge.
    AUTHFILE_HMAC_MD5_RESPONSE,  ///< HMAC-MD5 check response: input client response, buffer contains challenge, no output.
    AUTHFILE_HMAC_MD5_SERVER,    ///< HMAC-MD5 server authentication: input client challenge, output response.
} authfile_method_t;

/**
 * Function type for authentication source parser.
 *
 * @param filespec authentication source specification.
 * @return opaque handle that can be used for other calls.
 */
typedef void *(*authfile_parser_t)(const char *filespec);
/**
 * Function type for authentication callback.
 *
 * @param handle  opaque source handle.
 * @param method  authentication method.
 * @param user    user name, or NULL for support check.
 * @param input   input data, or NULL.
 * @param inplen  length of input data.
 * @param buffer  buffer for output data, or NULL.
 * @param bufsize buffer size.
 * @return length of output data or zero on success, or -1 on error.
 */
typedef ssize_t (*authfile_callback_t)(void *handle, authfile_method_t method, const char *user,
                                       const unsigned char *input, size_t inplen,
                                       unsigned char *buffer, size_t bufsize);

/**
 * Authentication source format.
 */
typedef struct {
    const char          *prefix;   ///< Format prefix
    authfile_parser_t    parse;    ///< Format parser function
    authfile_callback_t  callback; ///< Format authentication callback.
} authfile_format_t;

int authfile_anonymous(int flag);
int authfile_supported(authfile_method_t method);
void authfile_parse(const char *filespec);
const void *authfile_find_user(const char *user, authfile_method_t method);
ssize_t authfile_callback(const void *source, authfile_method_t method, const char *user,
                          const unsigned char *input, size_t inplen,
                          unsigned char *buffer, size_t bufsize);

// Format-specific functions follow here
void *authpwd_parse(const char *filespec);
ssize_t authpwd_callback(void *handle, authfile_method_t method, const char *user,
                         const unsigned char *input, size_t inplen,
                         unsigned char *buffer, size_t bufsize);

/**
 * @file
 * Definitions for authentication methods.
 */

/**
 * Authentication context
 */
typedef struct {
    const char *username;         ///< [OUT] Authenticated user name.
    const char *groupname;        ///< [OUT] Authenticated user group name.
    void       *authdata;         ///< [OUT] Authentication data, if any (malloc'ed).

    const unsigned char
               *challenge;        ///< [IN] Challenge data.
    size_t      challenge_length; ///< [IN] Challenge length.

    // NOTE: Challenge and response buffer may overlap!
    unsigned char
               *response;         ///< [IN/OUT] Response buffer/data.
    size_t      response_maxlen;  ///< [IN] Response buffer size.
    size_t      response_length;  ///< [OUT] Response length.
} auth_context_t;

/**
 * Function type for authentication stage callback.
 *
 * @param logprefix prefix for logging messages.
 * @param stage     stage number (zero-based).
 * @param ctxt      authentication context.
 * @return zero when complete, or +1 to continue, or -1 on error.
 */
typedef int (*auth_callback_t)(const char *logprefix, int stage, auth_context_t *ctxt);

/**
 * Authentication method descriptor.
 */
typedef struct {
    int method;                   ///< Method code
    const char *name;             ///< Method name
    auth_callback_t callback;     ///< Method stage callback
} auth_method_t;

const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen);

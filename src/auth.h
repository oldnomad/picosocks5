/**
 * @file
 * Definitions for authentication methods.
 */

/**
 * Authentication context
 */
typedef struct {
    const char *username;         ///< [OUT] Authenticated user name
    void       *authdata;         ///< [OUT] Authentication data, if any (malloc'ed)

    const unsigned char
               *challenge;        ///< [IN] Challenge data
    size_t      challenge_length; ///< [IN] Challenge length

    // NOTE: Challenge and response buffer may overlap!
    unsigned char
               *response;         ///< [IN/OUT] Response buffer/data
    size_t      response_maxlen;  ///< [IN] Response buffer size
    size_t      response_length;  ///< [OUT] Response length
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
 * Function type for authentication secret generator.
 *
 * @param secret  secret text.
 * @param buffer  buffer for secret data.
 * @param bufsize size of buffer.
 * @return size of generated data, or -1 on error.
 */
typedef ssize_t (*auth_generator_t)(const char *secret, char *buffer, size_t bufsize);

/**
 * Authentication method descriptor.
 */
typedef struct {
    int method;                   ///< Method code
    const char *name;             ///< Method name
    auth_callback_t callback;     ///< Method stage callback
    auth_generator_t generator;   ///< Method secret generator
} auth_method_t;

const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen);
const auth_method_t *auth_find_method(const char *name);
const auth_method_t *auth_all_methods(void);

extern const char   BASE64_PREFIX[];
extern const size_t BASE64_PREFIX_LEN;

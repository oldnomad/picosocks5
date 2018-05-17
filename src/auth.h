typedef struct {
    const void *auth;
    const unsigned char
          *challenge;
    size_t challenge_length;
    // NOTE: Challenge and response buffer may overlap!
    unsigned char
          *response;
    size_t response_maxlen;
    size_t response_length;
} auth_context_t;

typedef int (*auth_callback_t)(const char *peername, int stage, auth_context_t *ctxt);

typedef struct {
    int method;
    auth_callback_t callback;
} auth_method_t;

const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen);
const char *auth_get_username(const void *auth);

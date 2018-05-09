int auth_anon_allow(int newstate);
int auth_username_append(int method, const char *username, const char *secret, size_t secretlen);
const char *auth_get_username(const void *auth);

void authfile_parse(const char *filespec);

typedef struct {
    const void  *auth;
    const unsigned char
          *challenge;
    size_t challenge_length;
    // NOTE: Challenge and response buffer may overlap!
    unsigned char
          *response;
    size_t response_maxlen;
    size_t response_length;
} auth_context_t;

typedef struct {
    int method;
    int (*callback)(const char *peername, int stage, auth_context_t *ctxt);
} auth_method_t;

const auth_method_t *auth_negotiate_method(const unsigned char *offer, size_t offerlen);

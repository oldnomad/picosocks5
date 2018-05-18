typedef struct auth_user {
    int method;             // Auth method code
    const char *username;   // Username
    const char *secret;     // Secret (method-specific)
    size_t secretlen;       // Length of secret
} authuser_t;

int authuser_append(int method, const char *username, const char *secret, size_t secretlen);
int authuser_anon_allow(int newstate);
int authuser_method_allowed(int method);
const authuser_t *authuser_find(int method, const char *username, const authuser_t *cur);

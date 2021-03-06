/**
 * @file
 * Definitions for utility functions.
 */

uid_t util_parse_user(const char *user);
gid_t util_parse_group(const char *group);

#define UTIL_ADDRSTRLEN 64 ///< Maximum length of IPv[46] address string.
struct sockaddr;
int util_decode_addr(const struct sockaddr *addr, socklen_t addrlen, char *buffer, size_t bufsize);
int util_decode_network(const struct sockaddr *addr, socklen_t addrlen, unsigned bits, char *buffer, size_t bufsize);

ssize_t util_base64_encode(const void *data, size_t datalen, char *buffer, size_t bufsize);
ssize_t util_base64_decode(const char *text, void *buffer, size_t bufsize);

extern const char   BASE64_PREFIX[];
extern const size_t BASE64_PREFIX_LEN;

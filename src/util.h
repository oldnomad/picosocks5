uid_t util_parse_user(const char *user);
gid_t util_parse_group(const char *group);

#define UTIL_ADDRSTRLEN 64
int util_decode_addr(const struct sockaddr *addr, socklen_t addrlen, char *buffer, size_t bufsize);

struct sockaddr;
int acl_check_client_address(const struct sockaddr *addr, size_t addrlen);

int acl_add_client_network(const char *group, int allow, const char *address, unsigned bits);
void acl_show_config(void);

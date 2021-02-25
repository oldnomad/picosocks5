/**
 * @file
 * Definitions for ACL functions.
 */

struct sockaddr;
int acl_check_client_address(const char *group, const struct sockaddr *addr, size_t addrlen);
int acl_check_request(const char *group, unsigned char type, const struct sockaddr *addr, size_t addrlen);

int acl_set_parent(const char *group, const char *parent);
int acl_add_client_network(const char *group, int allow, const char *address, unsigned bits);
int acl_find_request_type(const char *name, ssize_t len);
const char *acl_get_request_type_name(int type);
int acl_add_request_rule(const char *group, int allow, int type, const char *address, unsigned bits);
void acl_show_config(void);

/**
 * @file
 * Definitions for proxy functions.
 */

int socks_set_bind_if(const char *host);
void socks_set_maxconn(unsigned long maxconn);
void socks_set_timeout(time_t sec, suseconds_t usec);

void socks_show_config(void);
int socks_listen_at(const char *host, const char *service, fd_set *fds);
void socks_accept_loop(int nfds, const fd_set *fds);

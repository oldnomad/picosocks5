int socks_set_bind_if(const char *host);
void socks_show_bind_if(void);
int socks_listen_at(const char *host, const char *service, fd_set *fds);
void socks_accept_loop(int nfds, const fd_set *fds);

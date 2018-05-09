#define LOGGER_SYSLOG 0x0001
#define LOGGER_STDERR 0x0002

void logger_init(int mode, int verbosity);
void logger(int prio, const char *msg, ...);

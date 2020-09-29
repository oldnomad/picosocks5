int logger_name2mode(const char *name);
int logger_name2level(const char *name);
const char *logger_mode2name(int mode);
const char *logger_level2name(int level);

int logger_need_nofork(int mode);
void logger_init(int nofork, int mode, int level);
#ifdef va_start
__attribute__(( __format__(__printf__, 2, 0) ))
void logger_vararg(int prio, const char *msg, va_list args);
#endif // va_start
__attribute__(( __format__(__printf__, 2, 3) ))
void logger(int prio, const char *msg, ...);

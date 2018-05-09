#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include "logger.h"

static int LOGMODE = LOGGER_SYSLOG;
static int VERBOSITY = LOG_DEBUG;

void logger_init(int mode, int verbosity)
{
    LOGMODE = mode;
    if (LOGMODE == 0)
        LOGMODE = LOGGER_SYSLOG;
    if ((LOGMODE & LOGGER_SYSLOG) != 0)
        openlog(PACKAGE, LOG_PID|LOG_CONS, LOG_DAEMON);
    VERBOSITY = verbosity;
}

void logger(int prio, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    if ((LOGMODE & LOGGER_SYSLOG) != 0)
        vsyslog(prio, msg, args);
    if ((LOGMODE & LOGGER_STDERR) != 0 && prio <= VERBOSITY)
    {
        vfprintf(stderr, msg, args);
        putc('\n', stderr);
        fflush(stderr);
    }
    va_end(args);
}

#include "config.h"
#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>
#include <syslog.h>
#include "logger.h"

void logger_vararg(int prio, const char *msg, va_list args)
{
    char text[1024] = "???";

    vsnprintf(text, sizeof(text), msg, args);
    fprintf(stderr, "LOGGER[%d]: %s", prio, text);
    if (prio != LOG_NOTICE && prio != LOG_INFO && prio != LOG_DEBUG)
        function_called();
}

void logger(int prio, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    logger_vararg(prio, msg, args);
    va_end(args);
}

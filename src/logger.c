/**
 * @file
 * Logger functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include "logger.h"

#define LOGGER_SYSLOG 0x0001 ///< Flag for output to syslog(3).
#define LOGGER_STDERR 0x0002 ///< Flag for output to stderr

static int LOGMODE = LOGGER_STDERR; ///< Logger mode (flags).
static int VERBOSITY = LOG_INFO; ///< Logger verbosity.

/**
 * List of known logger modes.
 */
static const struct {
    int mode;           ///< Mode flags.
    const char *name;   ///< Mode name.
} MODES[] = {
    { LOGGER_SYSLOG,               "syslog"   },
    { LOGGER_STDERR,               "stderr"   },
    { LOGGER_SYSLOG|LOGGER_STDERR, "combined" },
    { 0, NULL }
};
/**
 * List of known logger verbosity levels.
 */
static const struct {
    int level;          ///< Verbosity level.
    const char *name;   ///< Level name.
} LEVELS[] = {
    { 0,           "none"   },
    { LOG_ERR,     "error"  },
    { LOG_WARNING, "warn"   },
    { LOG_NOTICE,  "notice" },
    { LOG_INFO,    "info"   },
    { LOG_DEBUG,   "debug"  },
    { 0, NULL }
};

/**
 * Find logger mode by name.
 *
 * @param name mode name.
 * @return mode flags, or -1 on error.
 */
int logger_name2mode(const char *name)
{
    int i;

    for (i = 0; MODES[i].name != NULL; i++)
        if (strcasecmp(name, MODES[i].name) == 0)
            return MODES[i].mode;
    return -1;
}

/**
 * Find logger mode name by flags.
 *
 * @param mode mode flags.
 * @return mode name, or NULL if not found.
 */
const char *logger_mode2name(int mode)
{
    int i;

    for (i = 0; MODES[i].name != NULL; i++)
        if (mode == MODES[i].mode)
            return MODES[i].name;
    return NULL;
}

/**
 * Find logger level by name.
 *
 * @param name level name.
 * @return logger level, or -1 if not found.
 */
int logger_name2level(const char *name)
{
    int i;

    for (i = 0; LEVELS[i].name != NULL; i++)
        if (strcasecmp(name, LEVELS[i].name) == 0)
            return LEVELS[i].level;
    return -1;
}

/**
 * Find logger level name by value.
 *
 * @param level logger level.
 * @return level name, or NULL if not found.
 */
const char *logger_level2name(int level)
{
    int i;

    for (i = 0; LEVELS[i].name != NULL; i++)
        if (level == LEVELS[i].level)
            return LEVELS[i].name;
    return NULL;
}

/**
 * Check whether logger mode requires foreground.
 *
 * @param mode logger mode.
 * @return true if logger mode needs foreground.
 */
int logger_need_nofork(int mode)
{
    return (mode & LOGGER_STDERR) != 0;
}

/**
 * Initialize logger.
 *
 * @param nofork foreground flag.
 * @param mode   logger mode, or zero for default.
 * @param level  logger level, or -1 for default.
 */
void logger_init(int nofork, int mode, int level)
{
    LOGMODE = mode;
    if (LOGMODE == 0)
        LOGMODE = nofork ? LOGGER_STDERR : LOGGER_SYSLOG;
    if ((LOGMODE & LOGGER_SYSLOG) != 0)
        openlog(PACKAGE, LOG_PID|LOG_CONS, LOG_DAEMON);
    if (level >= 0)
        VERBOSITY = level;
}

/**
 * Log message (va_list-style).
 *
 * @param prio message priority.
 * @param msg  message format.
 * @param args message parameters.
 */
void logger_vararg(int prio, const char *msg, va_list args)
{
    if (prio > VERBOSITY)
        return;
    if ((LOGMODE & LOGGER_SYSLOG) != 0)
        vsyslog(prio, msg, args);
    if ((LOGMODE & LOGGER_STDERR) != 0)
    {
        vfprintf(stderr, msg, args);
        putc('\n', stderr);
        fflush(stderr);
    }
}

/**
 * Log message (varargs-style).
 *
 * @param prio message priority.
 * @param msg  message format.
 * @param ...  message parameters.
 */
void logger(int prio, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    logger_vararg(prio, msg, args);
    va_end(args);
}

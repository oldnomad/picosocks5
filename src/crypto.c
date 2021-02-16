/**
 * @file
 * Crypto functions.
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include "crypto.h"
#include "logger.h"

#ifndef HAVE_CRYPTO_MODULE
#define HAVE_CRYPTO_MODULE emul
#endif

#define HDR0(x) #x
#define HDR(x)  HDR0(x)
#define INC     crypto-HAVE_CRYPTO_MODULE.c

#include HDR(INC)

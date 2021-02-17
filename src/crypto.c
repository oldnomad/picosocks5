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

/**
 * Prefix for Base64 secret encoding
 */
const char   BASE64_PREFIX[]   = "$base64$";
/**
 * Length of prefix for Base64 secret encoding
 */
const size_t BASE64_PREFIX_LEN = sizeof(BASE64_PREFIX) - 1;

#ifndef HAVE_CRYPTO_MODULE
#define HAVE_CRYPTO_MODULE emul
#endif

/// Stringize.
#define HDR0(x) #x
/// Escape stringizing.
#define HDR(x)  HDR0(x)
/// Concatenate source file name.
#define INC     crypto-HAVE_CRYPTO_MODULE.c

#include HDR(INC)

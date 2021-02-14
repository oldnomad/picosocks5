/**
 * @file
 * Crypto functions (emulated).
 */
#include "config.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include "crypto.h"
#include "logger.h"

/*
 * NOTE: Functions in this file generate low-quality random nonce.
 *       But that's OK, since we only use it for password salt,
 *       not for any actual encryption.
 */

void crypto_init(void)
{
    srand(time(NULL));
}

void crypto_generate_nonce(unsigned char *buffer, size_t buflen)
{
    size_t i;

    for (i = 0; i < buflen; i++)
        *buffer++ = rand() & 0xFF;
}

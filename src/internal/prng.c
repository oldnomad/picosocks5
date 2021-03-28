/**
 * @file
 * PRNG implementation.
 *
 * Note that all PRNG functions are declared with additional
 * specifier, which is "static" by default; so, unless you
 * predefine it to something else, you should \#include the
 * implementation instead of linking to it.
 */
#include "config.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include "prng.h"

#if HAVE_GETENTROPY
#define init_entropy()
#else
static int URANDOM_HANDLE = -1;

static void init_entropy(void)
{
    URANDOM_HANDLE = open("/dev/urandom", O_RDONLY);
}

static int getentropy(void *buffer, size_t length)
{
    if (URANDOM_HANDLE < 0)
        return -1;
    return read(URANDOM_HANDLE, buffer, length) == length ? 0 : -1;
}
#endif

/**
 * Initialize PRNG.
 *
 * This function may be non-reenterable.
 */
PRNG_DECL void prng_init(void)
{
    init_entropy();
    srand(time(NULL));
}

/**
 * Generate pseudo-random data.
 *
 * @param buffer buffer for data.
 * @param size   size of buffer.
 */
PRNG_DECL void prng_generate(void *buffer, size_t size)
{
    unsigned char *ptr;
    size_t i, len;

    for (ptr = buffer; size != 0; size -= len, ptr += len)
    {
        len = (size > 256) ? 256 : size;
        if (getentropy(ptr, len) != 0)
            goto DEF_RAND;
    }
    return;
DEF_RAND:
    for (ptr = buffer, i = 0; i < size; i++)
        *ptr++ = rand() & 0xFF;
}

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
#include <time.h>
#include "prng.h"

/**
 * Initialize PRNG.
 *
 * This function may be non-reenterable.
 */
PRNG_DECL void prng_init(void)
{
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

#if HAVE_GETENTROPY
    {
        size_t len = 0;
        for (ptr = buffer; size != 0; size -= len, ptr += len)
        {
            len = (size > 256) ? 256 : size;
            if (getentropy(ptr, len) != 0)
                goto DEF_RAND;
        }
        return;
    }
#endif
DEF_RAND:
    {
        size_t i;
        for (ptr = buffer, i = 0; i < size; i++)
            *ptr++ = rand() & 0xFF;
    }
}

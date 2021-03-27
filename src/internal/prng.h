/**
 * @file
 * PRNG implementation definitions.
 *
 * Note that all PRNG functions are declared with additional
 * specifier, which is "static" by default; so, unless you
 * predefine it to something else, you should \#include the
 * implementation instead of linking to it.
 */
#ifndef PRNG_H_INCLUDED_
#define PRNG_H_INCLUDED_

#ifndef PRNG_DECL
#define PRNG_DECL static ///< Declaration specifier for PRNG functions.
#endif

PRNG_DECL void prng_init(void);
PRNG_DECL void prng_generate(void *buffer, size_t size);

#endif // PRNG_H_INCLUDED_

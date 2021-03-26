/**
 * @file
 * MD5 implementation definitions.
 *
 * Note that all MD5 functions are declared with additional
 * specifier, which is "static" by default; so, unless you
 * predefine it to something else, you should \#include the
 * implementation instead of linking to it.
 */
#ifndef MD5_H_INCLUDED_
#define MD5_H_INCLUDED_

#ifndef MD5_DECL
#define MD5_DECL static ///< Declaration specifier for MD5 functions.
#endif

/**
 * MD5 hash context.
 */
struct MD5Context {
    uint32_t buf[4];   ///< Collected intermediate hash.
    uint32_t in[16];   ///< Hashing block.
    uint32_t bytes[2]; ///< Number of bytes processed (64-bit).
};

MD5_DECL void MD5Init(struct MD5Context *context);
MD5_DECL void MD5Update(struct MD5Context *context, const unsigned char *buf, uint32_t len);
MD5_DECL void MD5Final(unsigned char digest[], struct MD5Context *context);

#endif // MD5_H_INCLUDED_

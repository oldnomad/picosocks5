/**
 * @file
 * Crypto functions (emulated).
 *
 * Implementation of MD5 in this file is based on classic public domain
 * code by Colin Plumb.
 */
#include <time.h>
#include <stdint.h>
#include <string.h>
#if HAVE_ENDIAN_H
#include <endian.h>
#endif

/*
 * NOTE: Functions in this file generate low-quality random nonce.
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

/**
 * MD5 hash context.
 */
struct MD5Context {
    uint32_t buf[4];   ///< Collected intermediate hash.
    uint32_t in[16];   ///< Hashing block.
    uint32_t bytes[2]; ///< Number of bytes processed (64-bit).
};

static void MD5Init(struct MD5Context *context);
static void MD5Update(struct MD5Context *context, const unsigned char *buf, uint32_t len);
static void MD5Final(unsigned char digest[], struct MD5Context *context);

#define CRYPTO_HMAC_BLKSIZE 64 ///< HMAC block size ("B").

int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen)
{
    /*
     * Code below follows RFC 2104 as close as possible.
     */
    struct MD5Context ctxt;
    unsigned char ipad[CRYPTO_HMAC_BLKSIZE];
    unsigned char opad[CRYPTO_HMAC_BLKSIZE];
    unsigned char keybuf[CRYPTO_MD5_SIZE];
    size_t i;

    if (reslen != CRYPTO_MD5_SIZE)
    {
        logger(LOG_ERR, "FATAL: MD5 hash length != %zu", reslen);
        exit(1);
    }
    if (keylen > CRYPTO_HMAC_BLKSIZE) {
        MD5Init(&ctxt);
        MD5Update(&ctxt, key, keylen);
        MD5Final(keybuf, &ctxt);
        key = keybuf;
        keylen = CRYPTO_MD5_SIZE;
    }
    memset(ipad, 0, CRYPTO_HMAC_BLKSIZE);
    memcpy(ipad, key, keylen);
    memset(opad, 0, CRYPTO_HMAC_BLKSIZE);
    memcpy(opad, key, keylen);
    for (i = 0; i < CRYPTO_HMAC_BLKSIZE; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }
    MD5Init(&ctxt);
    MD5Update(&ctxt, ipad, CRYPTO_HMAC_BLKSIZE);
    MD5Update(&ctxt, msg, msglen);
    MD5Final(res, &ctxt);

    MD5Init(&ctxt);
    MD5Update(&ctxt, opad, CRYPTO_HMAC_BLKSIZE);
    MD5Update(&ctxt, res, CRYPTO_MD5_SIZE);
    MD5Final(res, &ctxt);
    return 0;
}

/**********************************
 * MD5 implementation starts here *
 **********************************/
static void MD5Transform(struct MD5Context *ctx);

/**
 * Initialize MD5 context.
 *
 * @param ctx MD5 context.
 */
static void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    memset(ctx->in, 0, sizeof(ctx->in));

    ctx->bytes[0] = 0;
    ctx->bytes[1] = 0;
}

/**
 * Convert 32-bit words from little-endian to native order.
 *
 * @param words words to convert.
 * @param count number of words to convert.
 */
static inline void MD5WordsFromLE(uint32_t words[], size_t count)
{
    size_t i;

#ifdef le32toh
    for (i = 0; i < count; i++)
        words[i] = le32toh(words[i]);
#else
#error "For MD5 implementation to work, macro le32toh(x) should be defined"
#endif
}

/**
 * Convert 32-bit words from native order to little-endian.
 *
 * @param words words to convert.
 * @param count number of words to convert.
 */
static inline void MD5WordsToLE(uint32_t words[], size_t count)
{
    size_t i;

#ifdef htole32
    for (i = 0; i < count; i++)
        words[i] = htole32(words[i]);
#else
#error "For MD5 implementation to work, macro htole32(x) should be defined"
#endif
}

/**
 * Update MD5 context.
 *
 * @param ctx MD5 context.
 * @param buf data to add to the hash.
 * @param len size of added data.
 */
static void MD5Update(struct MD5Context *ctx, const unsigned char *buf, uint32_t len)
{
    uint32_t bsize, bfree;

    bsize = ctx->bytes[0];
    ctx->bytes[0] += len;
    if (ctx->bytes[0] < bsize) // Overflow; note that len is also 32-bit
        ctx->bytes[1]++;

    bsize = (bsize & 0x3f);
    bfree = 64 - bsize;
    if (len < bfree) {
        // Buffer incomplete
        memcpy((unsigned char *)ctx->in + bsize, buf, len);
        return;
    }
    memcpy((unsigned char *)ctx->in + bsize, buf, bfree);
    MD5WordsFromLE(ctx->in, 16);
    MD5Transform(ctx);
    buf += bfree;
    len -= bfree;

    for (; len >= 64; buf += 64, len -= 64) {
        memcpy(ctx->in, buf, 64);
        MD5WordsFromLE(ctx->in, 16);
        MD5Transform(ctx);
    }
    memcpy(ctx->in, buf, len);
}

/**
 * Finalize MD5 hash.
 *
 * @param digest buffer for MD5 hash value.
 * @param ctx MD5 context.
 */
static void MD5Final(unsigned char digest[], struct MD5Context *ctx)
{
    uint32_t bsize = ctx->bytes[0] & 0x3f;
    int bpad;
    unsigned char *p = (unsigned char *)ctx->in + bsize;

    // MD5Update guarantees there's at least 1 byte free
    *p++ = 0x80;
    bpad = 55 - (int)bsize; // 64 total, 8 bytes for size, 1 byte zero
    if (bpad < 0) {
        memset(p, 0, bpad + 8);
        MD5WordsFromLE(ctx->in, 16);
        MD5Transform(ctx);
        p = (unsigned char *)ctx->in;
        bpad = 56;
    }
    memset(p, 0, bpad);
    MD5WordsFromLE(ctx->in, 14);
    ctx->in[14] = ctx->bytes[0] << 3;
    ctx->in[15] = (ctx->bytes[1] << 3) | (ctx->bytes[0] >> 29);
    MD5Transform(ctx);

    MD5WordsToLE(ctx->buf, 4);
    memcpy(digest, ctx->buf, 16);
    MD5Init(ctx);
}

/**
 * Four code functions.
 * @{
 */
/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
/** @} */

/**
 * The central step of the MD5 algorithm.
 */
#define MD5STEP(f,w,x,y,z,in,s) \
    do { w += f(x,y,z) + in; w = (w<<s | w>>(32-s)) + x; } while (0)

/**
 * Transform single block for MD6 hash.
 *
 * @param ctx MD5 context.
 */
static void MD5Transform(struct MD5Context *ctx)
{
        uint32_t a, b, c, d;

        a = ctx->buf[0];
        b = ctx->buf[1];
        c = ctx->buf[2];
        d = ctx->buf[3];

        MD5STEP(F1, a, b, c, d, ctx->in[0] + 0xd76aa478, 7);
        MD5STEP(F1, d, a, b, c, ctx->in[1] + 0xe8c7b756, 12);
        MD5STEP(F1, c, d, a, b, ctx->in[2] + 0x242070db, 17);
        MD5STEP(F1, b, c, d, a, ctx->in[3] + 0xc1bdceee, 22);
        MD5STEP(F1, a, b, c, d, ctx->in[4] + 0xf57c0faf, 7);
        MD5STEP(F1, d, a, b, c, ctx->in[5] + 0x4787c62a, 12);
        MD5STEP(F1, c, d, a, b, ctx->in[6] + 0xa8304613, 17);
        MD5STEP(F1, b, c, d, a, ctx->in[7] + 0xfd469501, 22);
        MD5STEP(F1, a, b, c, d, ctx->in[8] + 0x698098d8, 7);
        MD5STEP(F1, d, a, b, c, ctx->in[9] + 0x8b44f7af, 12);
        MD5STEP(F1, c, d, a, b, ctx->in[10] + 0xffff5bb1, 17);
        MD5STEP(F1, b, c, d, a, ctx->in[11] + 0x895cd7be, 22);
        MD5STEP(F1, a, b, c, d, ctx->in[12] + 0x6b901122, 7);
        MD5STEP(F1, d, a, b, c, ctx->in[13] + 0xfd987193, 12);
        MD5STEP(F1, c, d, a, b, ctx->in[14] + 0xa679438e, 17);
        MD5STEP(F1, b, c, d, a, ctx->in[15] + 0x49b40821, 22);

        MD5STEP(F2, a, b, c, d, ctx->in[1] + 0xf61e2562, 5);
        MD5STEP(F2, d, a, b, c, ctx->in[6] + 0xc040b340, 9);
        MD5STEP(F2, c, d, a, b, ctx->in[11] + 0x265e5a51, 14);
        MD5STEP(F2, b, c, d, a, ctx->in[0] + 0xe9b6c7aa, 20);
        MD5STEP(F2, a, b, c, d, ctx->in[5] + 0xd62f105d, 5);
        MD5STEP(F2, d, a, b, c, ctx->in[10] + 0x02441453, 9);
        MD5STEP(F2, c, d, a, b, ctx->in[15] + 0xd8a1e681, 14);
        MD5STEP(F2, b, c, d, a, ctx->in[4] + 0xe7d3fbc8, 20);
        MD5STEP(F2, a, b, c, d, ctx->in[9] + 0x21e1cde6, 5);
        MD5STEP(F2, d, a, b, c, ctx->in[14] + 0xc33707d6, 9);
        MD5STEP(F2, c, d, a, b, ctx->in[3] + 0xf4d50d87, 14);
        MD5STEP(F2, b, c, d, a, ctx->in[8] + 0x455a14ed, 20);
        MD5STEP(F2, a, b, c, d, ctx->in[13] + 0xa9e3e905, 5);
        MD5STEP(F2, d, a, b, c, ctx->in[2] + 0xfcefa3f8, 9);
        MD5STEP(F2, c, d, a, b, ctx->in[7] + 0x676f02d9, 14);
        MD5STEP(F2, b, c, d, a, ctx->in[12] + 0x8d2a4c8a, 20);

        MD5STEP(F3, a, b, c, d, ctx->in[5] + 0xfffa3942, 4);
        MD5STEP(F3, d, a, b, c, ctx->in[8] + 0x8771f681, 11);
        MD5STEP(F3, c, d, a, b, ctx->in[11] + 0x6d9d6122, 16);
        MD5STEP(F3, b, c, d, a, ctx->in[14] + 0xfde5380c, 23);
        MD5STEP(F3, a, b, c, d, ctx->in[1] + 0xa4beea44, 4);
        MD5STEP(F3, d, a, b, c, ctx->in[4] + 0x4bdecfa9, 11);
        MD5STEP(F3, c, d, a, b, ctx->in[7] + 0xf6bb4b60, 16);
        MD5STEP(F3, b, c, d, a, ctx->in[10] + 0xbebfbc70, 23);
        MD5STEP(F3, a, b, c, d, ctx->in[13] + 0x289b7ec6, 4);
        MD5STEP(F3, d, a, b, c, ctx->in[0] + 0xeaa127fa, 11);
        MD5STEP(F3, c, d, a, b, ctx->in[3] + 0xd4ef3085, 16);
        MD5STEP(F3, b, c, d, a, ctx->in[6] + 0x04881d05, 23);
        MD5STEP(F3, a, b, c, d, ctx->in[9] + 0xd9d4d039, 4);
        MD5STEP(F3, d, a, b, c, ctx->in[12] + 0xe6db99e5, 11);
        MD5STEP(F3, c, d, a, b, ctx->in[15] + 0x1fa27cf8, 16);
        MD5STEP(F3, b, c, d, a, ctx->in[2] + 0xc4ac5665, 23);

        MD5STEP(F4, a, b, c, d, ctx->in[0] + 0xf4292244, 6);
        MD5STEP(F4, d, a, b, c, ctx->in[7] + 0x432aff97, 10);
        MD5STEP(F4, c, d, a, b, ctx->in[14] + 0xab9423a7, 15);
        MD5STEP(F4, b, c, d, a, ctx->in[5] + 0xfc93a039, 21);
        MD5STEP(F4, a, b, c, d, ctx->in[12] + 0x655b59c3, 6);
        MD5STEP(F4, d, a, b, c, ctx->in[3] + 0x8f0ccc92, 10);
        MD5STEP(F4, c, d, a, b, ctx->in[10] + 0xffeff47d, 15);
        MD5STEP(F4, b, c, d, a, ctx->in[1] + 0x85845dd1, 21);
        MD5STEP(F4, a, b, c, d, ctx->in[8] + 0x6fa87e4f, 6);
        MD5STEP(F4, d, a, b, c, ctx->in[15] + 0xfe2ce6e0, 10);
        MD5STEP(F4, c, d, a, b, ctx->in[6] + 0xa3014314, 15);
        MD5STEP(F4, b, c, d, a, ctx->in[13] + 0x4e0811a1, 21);
        MD5STEP(F4, a, b, c, d, ctx->in[4] + 0xf7537e82, 6);
        MD5STEP(F4, d, a, b, c, ctx->in[11] + 0xbd3af235, 10);
        MD5STEP(F4, c, d, a, b, ctx->in[2] + 0x2ad7d2bb, 15);
        MD5STEP(F4, b, c, d, a, ctx->in[9] + 0xeb86d391, 21);

        ctx->buf[0] += a;
        ctx->buf[1] += b;
        ctx->buf[2] += c;
        ctx->buf[3] += d;
}

#if 0
#include <stdio.h>

int main() {
    unsigned char res[CRYPTO_MD5_SIZE];
    int code;
    size_t i;

    code = crypto_hmac_md5("Jefe", 4, "what do ya want for nothing?", 28, res, sizeof(res));
    printf("Result: %d\n", code);
    printf("Hash: ");
    for (i = 0; i < sizeof(res); i++)
        printf("%02x", res[i]);
    printf("\n");
}
#endif

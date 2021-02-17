/**
 * @file
 * Definitions for cryptographic compatibility layer
 */

/**
 * Initialize cryptographic library
 */
void crypto_init(void);

/**
 * Generate some random data
 *
 * @param buffer buffer to fill.
 * @param buflen size of buffer.
 */
void crypto_generate_nonce(unsigned char *buffer, size_t buflen);

#if HAVE_CRYPTO_HMACMD5

#define CRYPTO_MD5_SIZE 16 ///< Size of MD5 hash, bytes

/**
 * Calculate HMAC-MD5 hash
 *
 * @param key    HMAC key.
 * @param keylen HMAC key length.
 * @param msg    message.
 * @param msglen message length.
 * @param res    buffer for resulting hash.
 * @param reslen size of buffer.
 * @return zero on success, or -1 on error.
 */
int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen);

#endif // HAVE_CRYPTO_HMACMD5

extern const char   BASE64_PREFIX[];
extern const size_t BASE64_PREFIX_LEN;

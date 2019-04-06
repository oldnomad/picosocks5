/**
 * Cryptographic compatibility layer
 */
#if HAVE_CRYPTO_LIB

/**
 * Initialize cryptographic library
 */
void crypto_init(void);

/**
 * Generate some random data
 */
void crypto_generate_nonce(unsigned char *buffer, size_t buflen);

#else // !HAVE_CRYPTO_LIB

#define crypto_init() ((void)0)

#endif // HAVE_CRYPTO_LIB

#if HAVE_CRYPTO_HMACMD5

#define CRYPTO_MD5_SIZE 16 // Size of MD5 hash, bytes

/**
 * Calculate HMAC-MD5 hash
 */
int crypto_hmac_md5(const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char *res, size_t reslen);

#endif // HAVE_CRYPTO_HMACMD5

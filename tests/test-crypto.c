#include "config.h"
#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>
#include "crypto.h"
#include "logger.h"

void logger_vararg(int prio, const char *msg, va_list args)
{
    char text[1024] = "???";

    vsnprintf(text, sizeof(text), msg, args);
    fail_msg("LOGGER: %s", text);
}

void logger(int prio, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    logger_vararg(prio, msg, args);
    va_end(args);
}

static int setup(void **state)
{
    crypto_init();
}

static void test_random(void **state)
{
    unsigned char buffer[512];

    (void)state;
    crypto_generate_nonce(buffer, sizeof(buffer));
}

static void test_hmac_md5(void **state)
{
    static const struct {
        unsigned char *key;
        size_t         keylen;
        unsigned char *msg;
        size_t         msglen;
        unsigned char *res;
    } TEST_VECTORS[] = {
        { "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
          "Hi There", 8,
          "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d" },
        { "Jefe", 4,
          "what do ya want for nothing?", 28,
          "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38" },
        { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 16,
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
          "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 50,
          "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6" },
        { NULL }
    };
    size_t i;

    (void)state;
    for (i = 0; TEST_VECTORS[i].key != NULL; i++)
    {
        unsigned char res[CRYPTO_MD5_SIZE];
        int code = crypto_hmac_md5(TEST_VECTORS[i].key, TEST_VECTORS[i].keylen,
            TEST_VECTORS[i].msg, TEST_VECTORS[i].msglen, res, sizeof(res));
        assert_memory_equal(res, TEST_VECTORS[i].res, sizeof(res));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_random),
        cmocka_unit_test(test_hmac_md5),
    };
    return cmocka_run_group_tests(tests, setup, NULL);
}

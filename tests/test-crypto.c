#include "config.h"
#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>
#include "crypto.h"

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
        // Tests from RFC 2202
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
        { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
          "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
          "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
          "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
          "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
          "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
          "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD", 50,
          "\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79" },
        { "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 16,
          "Test With Truncation", 20,
          "\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c" },
        { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 80,
          "Test Using Larger Than Block-Size Key - Hash Key First", 54,
          "\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd" },
        { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
          "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 80,
          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73,
          "\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e" },
        { NULL }
    };
    size_t i;

    (void)state;
    for (i = 0; TEST_VECTORS[i].key != NULL; i++)
    {
        unsigned char res[CRYPTO_MD5_SIZE];
        print_message("-- HMAC-MD5 test %zu\n", i + 1);
        int code = crypto_hmac_md5(TEST_VECTORS[i].key, TEST_VECTORS[i].keylen,
            TEST_VECTORS[i].msg, TEST_VECTORS[i].msglen, res, sizeof(res));
        assert_int_equal(code, 0);
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

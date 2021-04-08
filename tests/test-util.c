#include "config.h"
#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "util.h"

#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define htons_constant(x) (x)
#define htonl_constant(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define htons_constant(x) __bswap_constant_16(x)
#define htonl_constant(x) __bswap_constant_32(x)
#else
#error "This test won't work unless endianness is LE or BE"
#endif

static void test_parse(void **state)
{
    print_message("-- User/group name test\n");
    assert_int_equal(util_parse_user("root"), 0);
    assert_int_equal(util_parse_group("root"), 0);

    print_message("-- User/group numeric value test\n");
    assert_int_equal(util_parse_user("12345"), 12345);
    assert_int_equal(util_parse_group("12345"), 12345);
}

static void test_decode_addr(void **state)
{
    static const struct {
        union all_addr {
            struct sockaddr         sa;
            struct sockaddr_in      sin;
            struct sockaddr_in6     sin6;
            struct sockaddr_storage ss;
        }           addr;
        unsigned    bits;
        const char *addr_text;
        const char *net_text;
    } TEST_VECTORS[] = {
        { { .sa = {
              .sa_family = AF_UNSPEC
          }}, 0, "[???]:?", "*/0" },
        { { .sin = {
              .sin_family = AF_INET,
              .sin_addr = htonl_constant(INADDR_LOOPBACK),
              .sin_port = htons_constant(12345)
          }}, 8, "127.0.0.1:12345", "127.0.0.1/8" },
        { { .sin6 = {
              .sin6_family = AF_INET6,
              .sin6_addr = IN6ADDR_LOOPBACK_INIT,
              .sin6_port = htons_constant(12345)
          }}, 64, "[::1]:12345", "[::1]/64" },
        { { .sa = { .sa_family = 256 }} }
    };
    size_t i;
    char buffer[256];
    int rlen;

    for (i = 0; TEST_VECTORS[i].addr.sa.sa_family != 256; i++)
    {
        print_message("-- Address decode test %zu\n", i + 1);

        rlen = util_decode_addr(&TEST_VECTORS[i].addr.sa, sizeof(TEST_VECTORS[i].addr), buffer, sizeof(buffer));
        assert_return_code(rlen, 0);
        assert_string_equal(buffer, TEST_VECTORS[i].addr_text);

        rlen = util_decode_network(&TEST_VECTORS[i].addr.sa, sizeof(TEST_VECTORS[i].addr), TEST_VECTORS[i].bits, buffer, sizeof(buffer));
        assert_return_code(rlen, 0);
        assert_string_equal(buffer, TEST_VECTORS[i].net_text);
    }
}

static void test_base64(void **state)
{
    static const struct {
        const char *text;
        size_t      textlen;
        const char *encoded;
    } TEST_VECTORS[] = {
        // Tests from RFC 4648
        { "",       0, "" },
        { "f",      1, "Zg==" },
        { "fo",     2, "Zm8=" },
        { "foo",    3, "Zm9v" },
        { "foob",   4, "Zm9vYg==" },
        { "fooba",  5, "Zm9vYmE=" },
        { "foobar", 6, "Zm9vYmFy" },
        { NULL }
    };
    size_t i, elen;
    ssize_t rlen;
    char buffer[16];

    (void)state;
    for (i = 0; TEST_VECTORS[i].text != NULL; i++)
    {
        print_message("-- Base64 test %zu\n", i + 1);
        elen = strlen(TEST_VECTORS[i].encoded);

        rlen = util_base64_encode(TEST_VECTORS[i].text, TEST_VECTORS[i].textlen, buffer, sizeof(buffer));
        assert_int_equal(rlen, elen);
        assert_memory_equal(buffer, TEST_VECTORS[i].encoded, rlen);

        rlen = util_base64_decode(TEST_VECTORS[i].encoded, buffer, sizeof(buffer));
        assert_int_equal(rlen, TEST_VECTORS[i].textlen);
        assert_memory_equal(buffer, TEST_VECTORS[i].text, rlen);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse),
        cmocka_unit_test(test_decode_addr),
        cmocka_unit_test(test_base64),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

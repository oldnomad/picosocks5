check_PROGRAMS =
TESTS =

if CMOCKA_PRESENT

check_PROGRAMS += crypto
TESTS += crypto
crypto_SOURCES = test-crypto.c ../src/crypto.c
crypto_CFLAGS = -I../src
crypto_LDFLAGS = -lcmocka

endif CMOCKA_PRESENT

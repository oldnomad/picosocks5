check_PROGRAMS =
TESTS =

if LCOV_PRESENT
COV_CFLAGS = -O0 -fprofile-arcs -ftest-coverage

clean-local:
	-rm -f *.gcda *.gcno
	-rm -f ../src/*.gcda ../src/*.gcno
else !LCOV_PRESENT
COV_CFLAGS =
endif !LCOV_PRESENT

if CMOCKA_PRESENT

check_PROGRAMS += crypto
TESTS += crypto
crypto_SOURCES = test-crypto.c ../src/crypto.c
crypto_CFLAGS = -I../src $(COV_CFLAGS)
crypto_LDFLAGS = -lcmocka

endif CMOCKA_PRESENT

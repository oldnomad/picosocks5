check_PROGRAMS =
TESTS =

TESTS_CFLAGS_APP = -I../src

#
# Flags and rules for lcov/gcov
#
if LCOV_PRESENT
COV_CFLAGS_APP = -O0 -fprofile-arcs -ftest-coverage
COV_LDFLAGS_APP =

clean-local:
	-rm -f *.gcda *.gcno
	-rm -f ../src/*.gcda ../src/*.gcno
else !LCOV_PRESENT
COV_CFLAGS_APP =
COV_LDFLAGS_APP =
endif !LCOV_PRESENT

#
# Tests using cmocka
#
if CMOCKA_PRESENT

CMOCKA_CFLAGS_APP =
CMOCKA_LDFLAGS_APP = -lcmocka

check_PROGRAMS += crypto
TESTS += crypto
crypto_SOURCES = test-crypto.c ../src/crypto.c
crypto_CFLAGS = $(TESTS_CFLAGS_APP) $(COV_CFLAGS_APP) $(CMOCKA_CFLAGS_APP)
crypto_LDFLAGS = $(COV_LDFLAGS_APP) $(CMOCKA_LDFLAGS_APP)

check_PROGRAMS += util
TESTS += util
util_SOURCES = test-util.c ../src/util.c
util_CFLAGS = $(TESTS_CFLAGS_APP) $(COV_CFLAGS_APP) $(CMOCKA_CFLAGS_APP)
util_LDFLAGS = $(COV_LDFLAGS_APP) $(CMOCKA_LDFLAGS_APP)

endif CMOCKA_PRESENT

AM_CFLAGS = -std=c99 -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
sbin_PROGRAMS = picosocks5
bin_PROGRAMS = pis5user

picosocks5_SOURCES = main.c socks5.c logger.c util.c \
    auth.c authuser.c auth-basic.c \
    authfile.c authfile-password.c
EXTRA_picosocks5_SOURCES = crypto-openssl.c
picosocks5_LDADD = $(CRYPTO_MODULE)
picosocks5_DEPENDENCIES = $(CRYPTO_MODULE)

pis5user_SOURCES = pis5-user.c logger.c util.c \
    auth.c authuser.c auth-basic.c
EXTRA_pis5user_SOURCES = crypto-openssl.c
pis5user_LDADD = $(CRYPTO_MODULE)
pis5user_DEPENDENCIES = $(CRYPTO_MODULE)

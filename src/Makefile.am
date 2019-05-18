AM_CFLAGS = -std=c99 -Wall -Wextra -pedantic -Wshadow -Wunused -Wuninitialized -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
sbin_PROGRAMS = picosocks5
bin_PROGRAMS = pis5user

picosocks5_SOURCES = main.c cmdline.c inifile.c logger.c util.c socks5.c \
    auth.c authuser.c auth-basic.c auth-chap.c \
    authfile.c authfile-password.c
EXTRA_picosocks5_SOURCES = crypto-gnutls.c crypto-openssl.c
picosocks5_LDADD = $(CRYPTO_MODULE)
picosocks5_DEPENDENCIES = $(CRYPTO_MODULE)

pis5user_SOURCES = pis5-user.c logger.c util.c \
    auth.c authuser.c auth-basic.c auth-chap.c
EXTRA_pis5user_SOURCES = crypto-gnutls.c crypto-openssl.c
pis5user_LDADD = $(CRYPTO_MODULE)
pis5user_DEPENDENCIES = $(CRYPTO_MODULE)

if HAVE_PANDOC
man1_MANS = pis5user.man
man8_MANS = picosocks5.man
endif
SUFFIXES =  .man .md
CLEANFILES = *.man

.md.man:
	pandoc -s -t man -o $@ $<

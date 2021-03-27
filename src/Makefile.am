AM_CFLAGS = -Wall -Wextra -pedantic -Wshadow -Wunused -Wuninitialized -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-signedness
sbin_PROGRAMS = picosocks5
bin_PROGRAMS = pis5user

picosocks5_SOURCES = main.c cmdline.c inifile.c logger.c util.c crypto.c \
    socks5.c acl.c auth.c authfile.c authfile-password.c

pis5user_SOURCES = pis5-user.c util.c

if HAVE_PANDOC
man1_MANS = pis5user.man
man8_MANS = picosocks5.man
endif
SUFFIXES =  .man .md
CLEANFILES = *.man

.md.man:
	pandoc -s -t man -o $@ $<

distclean-local: clean-doxygen

.PHONY: doxygen clean-doxygen

doxygen:
	mkdir -p doc/
	doxygen Doxyfile

clean-doxygen:
	rm -rf doc/

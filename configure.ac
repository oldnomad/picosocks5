AC_INIT([picosocks5], [0.5], [alec.kojaev@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
want_crypto=yes
AC_ARG_WITH([crypto],
            [AS_HELP_STRING([[--with-crypto[=LIBRARY]]],
                            [enable cryptographic support (supported:
                             gnutls, openssl, yes, no; default: yes)])],
            [want_crypto="$withval"])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AS_IF([test "x$ac_cv_prog_cc_c99" = xno],
      [AC_MSG_ERROR([compiler must support C99 standard])])

AC_CHECK_HEADERS([fcntl.h netdb.h stddef.h syslog.h termios.h unistd.h sys/socket.h])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([dup2 memchr memmove memset select socket strcasecmp strchr strrchr strtoul])

AC_SEARCH_LIBS(pthread_create, [pthread])
AC_SEARCH_LIBS(crypt_r, [crypt])

CRYPTO_LIBS=
CRYPTO_MODULE=
CRYPTO_HMACMD5=
AS_IF([test -z "$CRYPTO_LIBS" -a \( "x$want_crypto" = xyes -o "x$want_crypto" = xgnutls \)],
      [AC_CHECK_LIB([gnutls], [gnutls_check_version],
                    [CRYPTO_LIBS="-lgnutls"
                     CRYPTO_MODULE="crypto-gnutls.\$(OBJEXT)"
                     CRYPTO_HMACMD5="yes"
                    ])
      ])
AS_IF([test -z "$CRYPTO_LIBS" -a \( "x$want_crypto" = xyes -o "x$want_crypto" = xopenssl \)],
      [AC_CHECK_LIB([ssl], [SSL_CTX_new],
                    [CRYPTO_LIBS="-lssl -lcrypto"
                     CRYPTO_MODULE="crypto-openssl.\$(OBJEXT)"
                     AC_CHECK_LIB([crypto], [EVP_md5], [CRYPTO_HMACMD5="yes"])
                    ])
      ])
AS_IF([test -z "$CRYPTO_MODULE" -a "x$want_crypto" != xno],
      [AC_MSG_ERROR([unknown cryptographic library '$want_crypto' specified])])
AS_IF([test "x$CRYPTO_HMACMD5" = xyes ],
      [AC_DEFINE([HAVE_CRYPTO_LIB], [1], [Use cryptographic methods])
       AS_IF([test "x$CRYPTO_HMACMD5" = xyes],
             [AC_DEFINE([HAVE_CRYPTO_HMACMD5], [1], [Use HMAC-MD5 (RFC 2104, RFC 1321)])])
       LIBS="$CRYPTO_LIBS $LIBS"])
AC_SUBST([CRYPTO_MODULE])

AC_OUTPUT

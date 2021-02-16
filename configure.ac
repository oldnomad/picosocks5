AC_INIT([picosocks5], m4_esyscmd_s([./version.sh]), [alec.kojaev@gmail.com], [picosocks5], [https://gitlab.com/oldnomad/picosocks5])
m4_define([AC_PACKAGE_COPYRIGHT], [Copyright (c) 2018-2020 Alec Kojaev <alec.kojaev@gmail.com>])
AC_DEFINE([PACKAGE_COPYRIGHT], ["AC_PACKAGE_COPYRIGHT"], [Package copyright])
AC_COPYRIGHT([AC_PACKAGE_COPYRIGHT])
AC_MSG_NOTICE([detected version: AC_PACKAGE_VERSION])
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
AC_CHECK_PROG([PANDOC], [pandoc], [yes])
AS_IF([test "x${PANDOC}" = xyes],
      [],
      [AC_MSG_WARN([pandoc not found, man pages will not be built])])
AM_CONDITIONAL([HAVE_PANDOC], [test "x${PANDOC}" = xyes])

AC_CHECK_HEADERS([fcntl.h limits.h netdb.h stddef.h syslog.h termios.h unistd.h sys/socket.h],
                 [], [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([ifaddrs.h stdatomic.h])
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_CHECK_TYPES([atomic_ulong], [], [], [[#include <stdatomic.h>]])
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRTOD
AC_CHECK_FUNCS([dup2 memchr memmove memset select socket strcasecmp strchr strrchr strdup strtod strtoul],
               [], [AC_MSG_ERROR([missing required function])])
AC_CHECK_FUNCS([getifaddrs])
AS_IF([test "x$ac_cv_func_getifaddrs" = xyes],
      [AC_DEFINE([HAVE_IFADDRS_SUPPORT], [1], [Support interface names in bind options])])
AS_IF([test "x$ac_cv_type_atomic_ulong" = xyes -a "x$ac_cv_header_stdatomic_h" = xyes],
      [AC_DEFINE([HAVE_STDC_ATOMICS], [1], [Support thread counters])])

AC_SEARCH_LIBS(pthread_create, [pthread],
               [], [AC_MSG_ERROR([missing pthread implementation])])
AC_SEARCH_LIBS(crypt_r, [crypt],
               [], [AC_MSG_ERROR([missing crypt_r implementation])])

CRYPTO_LIBS=
CRYPTO_MODULE="emul"
CRYPTO_HMACMD5=
AS_IF([test -z "$CRYPTO_LIBS" -a \( "x$want_crypto" = xyes -o "x$want_crypto" = xgnutls \)],
      [AC_CHECK_LIB([gnutls], [gnutls_check_version],
                    [CRYPTO_LIBS="-lgnutls"
                     CRYPTO_MODULE="gnutls"
                     CRYPTO_HMACMD5="yes"
                    ])
      ])
AS_IF([test -z "$CRYPTO_LIBS" -a \( "x$want_crypto" = xyes -o "x$want_crypto" = xopenssl \)],
      [AC_CHECK_LIB([ssl], [SSL_CTX_new],
                    [CRYPTO_LIBS="-lssl -lcrypto"
                     CRYPTO_MODULE="openssl"
                     AC_CHECK_LIB([crypto], [EVP_md5], [CRYPTO_HMACMD5="yes"])
                    ])
      ])
AS_IF([test -z "$CRYPTO_MODULE" -a "x$want_crypto" != xno],
      [AC_MSG_ERROR([unknown cryptographic library '$want_crypto' specified])])

AS_IF([test "x$CRYPTO_HMACMD5" = xyes ],
      [AC_DEFINE([HAVE_CRYPTO_HMACMD5], [1], [Use HMAC-MD5 (RFC 2104, RFC 1321)])])
LIBS="$CRYPTO_LIBS $LIBS"
AC_DEFINE_UNQUOTED([HAVE_CRYPTO_MODULE], [$CRYPTO_MODULE], [Crypto module to use])

AC_OUTPUT

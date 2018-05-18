AC_INIT([picosocks5], [0.1], [alec.kojaev@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AS_IF([test "x$ac_cv_prog_cc_c99" = xno], [AC_MSG_ERROR([compiler must support C99 standard])])

AC_CHECK_HEADERS([fcntl.h netdb.h stddef.h syslog.h unistd.h sys/socket.h])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([dup2 memchr memmove select socket strcasecmp strchr strrchr strtoul])

AC_SEARCH_LIBS(pthread_create, [pthread])
AC_SEARCH_LIBS(crypt_r, [crypt])

AC_OUTPUT

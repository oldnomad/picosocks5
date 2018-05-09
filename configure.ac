AC_INIT([picosocks5], [0.1], [alec.kojaev@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS([fcntl.h netdb.h syslog.h unistd.h sys/socket.h])
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_FUNC_FORK
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([dup2 memchr memmove select socket strtoul])
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(crypt, crypt_r)

AC_OUTPUT

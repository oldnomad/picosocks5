# How to extend PicoSOCKS5

## How to add a crypto library

PicoSOCKS5 can be compiled with GnuTLS or OpenSSL, and even without any crypto
library at all (though in this case it doesn't support CHAP authentication).
To compile PicoSOCKS5 with a new crypto library you have to perform two tasks:

  1. Write a wrapper for the library.
  2. Integrate the wrapper into the configure script.

First, you have to decide three parameters:

  - Choose a unique name ("module name") by which the crypto library will
    be known in th configuration script. Lower case and no spaces is the
    preferred format. Names "yes", "no", "emul", "gnutls", and "openssl"
    must not be used.
  - Choose a list of options that must be passed to the compiler when
    linking with the library.
  - Choose whether you want to implement HMAC-MD5. If it's implemented,
    PicoSOCKS5 will be able to use CHAP authentication.

### Writing a wrapper

  - Crypto library wrapper is a C source file, which is included into file
    `src/crypto.c`. It may omit some includes that are already made in the
    including file.
  - The wrapper source file must reside in `src/` and its name must have
    format `crypto-NAME.c`, where `NAME` is the chosen crypto module name.
  - The wrapper must implement methods `crypto_init` and
    `crypto_generate_nonce`, and may implement `crypto_hmac_md5` (used for
    CHAP authentication), Signatures for these methods are specified in file
    `src/crypto.h`.

For reference look at implemented wrappers (`src/crypto-gnutls.c` and
`src/crypto-openssl.c`).

### Integrating into configuration script

To integrate your wrapper into the configure script, you have to add
corresponding `autoconf` tests into `configure.ac`. The place that has to be
modified can be found between comments `### ADD CUSTOM CRYPTO MODULES BELOW`
and `### END OF CUSTOM CRYPTO MODULES`.

For inspiration look at GnuTLS and OpenSSL module blocks above the comments.

Your code must check that your crypto module was chosen, check whether the
library you need is installed, and set following variables:

  - `CRYPTO_MODULE` is set to your crypto module name.
  - `CRYPTO_LIBS` must be set to additional compiler options needed for
    linking.
  - `CRYPTO_HMACMD5` must be set to `yes` if the implementor chose to
    implement HMAC-MD5.

In the example below:

  - The crypto module name is `my_lib`.
  - Linking requires compiler option `-lmy_lib_name`, and the library has
    function `my_lib_function` that can be used for library detection.
  - The implementor chose to implement HMAC-MD5.

```
AS_IF([test -z "$CRYPTO_MODULE" -a \( "x$want_crypto" = xyes -o "x$want_crypto" = xmy_lib \)],
      [AC_MSG_NOTICE([checking for MyLib crypto module])
       AC_CHECK_LIB([my_lib_name], [my_lib_function],
                    [CRYPTO_MODULE="my_lib"
                     CRYPTO_LIBS="-lmy_lib_name"
                     CRYPTO_HMACMD5="yes"
                    ])
      ])
```

## How to add an authentication source format

Currently PicoSOCKS5 supports only one authorization source format:
a plain-text password file. To define a new authorization source
(for example, LDAP) you have to write a a C source file with following
two functions:

  - A parser function fitting function type `authfile_parser_t` defined
    in file `src/authfile.h`. This function gets a source specification
    (in some unspecified format) and "parses" it. What this operation
    means depends on the nature of the source, but it should result in
    an opaque handle (a pointer to unspecified data) that allows further
    calls of the callback function (see below) to access the source.
    Note that the parser function is called before daemonization. That
    means that error messages should be printed to `stderr` and that a
    `fork()` might occur between return from the parser function and
    the first use of the handle returned by it.

  - A callback function fitting function type `authfile_callback_t`
    defined in file `src/authfile.h`. This function will be called
    at various stages of authentication process. More details on this
    below.

Recommended file name for C source implementing these function is
`authfile-NAME.c`, where `NAME` identifies source format. You should
also select a prefix that will be used when specifying sources in
this format.

Once the implementation is ready, you'll have to:

  1. Add function prototypes for your implementation to the end
     of header `src/authfile.h`.
  2. Add a descriptor containing selected prefix, and pointers
     to parser and callback functions to array `FILE_FORMATS`
     in file `src/authfile.c`.
  3. Add your source file(s) to `picosocks5_SOURCES` in file
     `src/Makefile.am`.

### Callback function

The callback function accepts following parameters:

  - `handle`: opaque handle returned by the parser function.
  - `method`: flag indicating what behaviour is expected from the
    callback function in this call.
  - `user`: user name of the user being authenticated. This
    parameter can be NULL for method check (see below).
  - `input` and `inplen`: pointer to input data and length of
    the data. Exact meaning of the input data depends on the
    method.
  - `buffer` and `bufsize`L pointer to output buffer and its
    size. Exact purpose and contents of the buffer depends on
    the method.

The callback must handle a call with NULL value of `user`
parameter as a check whether the callback supports the method
specified in parameter `method`. The callback must return
zero if the method is supported, or `-1` otherwise.

Following methods are defined:

  - `AUTHFILE_CHECK`: Check whether specified user can be
    authenticated by this source (exists). The callback returns
    zero if user exists, or `-1` otherwise. Input data and
    output buffer are ignored.
  - `AUTHFILE_LOGIN`: Plaintext login, input data contains
    plaintext password (not NUL-terminated). The password
    is guaranteed to be at most 255 bytes long. The callback
    returns zero on successful login, or `-1` otherwise.
    Output buffer is ignored.
  - `AUTHFILE_HMAC_MD5_CHALLENGE`: Challenge stage of HMAC-MD5
    authentication. The callback is expected to generate a
    challenge in the output buffer and return its length on
    success, or `-1` on error. Input data is ignored.
  - `AUTHFILE_HMAC_MD5_RESPONSE`: Response stage of HMAC-MD5
    authentication. Input data contains client response to
    the challenge, and buffer contains the challenge generated
    on the previous stage. The callback returns zero on
    successful login, or `-1` otherwise.
  - `AUTHFILE_HMAC_MD5_SERVER`: Optional server response
    stage of HMAC-MD5 authentication. Input data contains
    challenge provided by the client. The callback is expected
    to generate a response in the output buffer and return
    its length on success, or `-1` on error.

The callback must implement method at least the method
`AUTHFILE_CHECK`. It must also properly handle call with
NULL parameter `user` (as described above) and check validity
of all parameters in calls that don't ignore these parameters.

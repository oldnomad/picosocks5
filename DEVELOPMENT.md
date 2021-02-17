# How to extend PicoSOCKS5

## How to add a crypto library

To compile PicoSOCKS5 with a new crypto library you have to perform two tasks:

  1. Write a wrapper for the library.
  2. Integrate the wrapper into the configure script.

First, you have to decide three parameters:

  - Choose a unique name ("module name") by which the crypro library will
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

## How to add an authentication method

//To be written...//

## How to add an authentication source format

//To be written...//

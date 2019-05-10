# PicoSOCKS5: a lightweight and simple SOCKS5 proxy server
[![pipeline status](https://gitlab.com/oldnomad/picosocks5/badges/master/pipeline.svg)](https://gitlab.com/oldnomad/picosocks5/commits/master)

PicoSOCKS5 is a SOCKS5 proxy server cobbled together in less than 5 days
of lazy coding. It is written in pure C and by default uses no extra
libraries besides GLibc.

# License

PicoSOCKS5 is licensed under GNU Generat Public License Version 3 (GPLv3).
For full text of the license see file [LICENSE.txt](LICENSE.txt) in the
root of the project.

In addition, linking to and/or using OpenSSL is allowed. This additional
permission is required since recent OpenSSL license is considered by some
to be incompatible with GPL.

# Supported features

- PicoSOCKS5 implements SOCKS5 ([RFC 1928](https://www.ietf.org/rfc/rfc1928.txt)).
  Currently only `CONNECT` and `BIND` are supported, but `UDP ASSOCIATE`
  may be implemented later. Earlier versions of SOCKS (SOCKS4, SOCKS4a)
  are not implemented. Drafts [SOCKS5a](https://www.ietf.org/archive/id/draft-ietf-aft-socks-pro-v5-05.txt),
  [SOCKS6](https://www.ietf.org/id/draft-olteanu-intarea-socks-6-06.txt),
  and other enhancements are not implemented.
- PicoSOCKS5 implements username/password authentication for SOCKS5
  ([RFC 1929](https://www.ietf.org/rfc/rfc1929.txt)).
- PicoSOCKS5 implements CHAP authentication for SOCKS5
  ([draft](https://www.ietf.org/archive/id/draft-ietf-aft-socks-chap-01.txt)),
  including mutual authentication. This support requires additional
  libraries (GnuTLS or OpenSSL).
- PicoSOCKS5 supports incoming and outgoing connections both in IPv4 and
  IPv6. In particular, it can accept requests to connect to IPv6 servers
  from IPv4 clients, and vice versa, serving as a gateway for mechanism
  described in [RFC 3089](https://www.ietf.org/rfc/rfc3089.txt).

# Known disadvantages

- PicoSOCKS5 has no limits on incoming connections, so it can be easily
  overwhelmed by a deliberate denial-of-service attack from client side.
- There's no access control (any client that can access the proxy can
  connect to any accessible server).
- User list for authentication is kept in memory, so PicoSOCKS5 doesn't
  work well for really large number of users.
- There's currently no support for GSS-API authentication method
  ([RFC 1961](https://www.ietf.org/rfc/rfc1961.txt)), required for full
  SOCKS5 compliance.
- There's currently no support for SOCKS-over-SSL
  ([draft](https://www.ietf.org/archive/id/draft-ietf-aft-socks-ssl-00.txt)).
  I'll be grateful for any pointers about existing implementations of
  this protocol variant.
- SOCKS5 `BIND` request support relies on "external" interface addresses
  specified in daemon configuration. Automatic interface selection is
  difficult to implement portably.

# Building PicoSOCKS5

For building PicoSOCKS5 you'll need:

- GCC compiler. Any version supporting C99 will do (v4.8.4 or newer is
  guaranteed to work). PicoSOCKS5 conforms to C99 standard, so it can be
  ported to any compiler supporting it.
- GLibc or compatible library. PicoSOCKS5 uses POSIX.1-2017 (with XSI
  extensions) and following GNU extensions:

  - `vsyslog(3)`.
  - `getopt_long(3)`.
  - `crypt_r(3)` and algorithm extensions for crypt(3) family.
  - Format specifier `"%m"` in `printf(3)` family.
  - Optionally, `getifaddrs(3)`. The program will compile without it,
    by when it's available, additional functionality is enabled.

  So if you have another POSIX-compliant C runtime library that includes
  these features, PicoSOCKS5 can be ported to it.
- If you want to enable CHAP authemtication method, you'll also need either
  GnuTLS or OpenSSL library. Following features are used:

  - Random bytes generation.
  - MD5 hash and HMAC functions.

- GNU Autoconf/Automake, and their dependencies. The project is built
  using automake version 1.15, but version 1.14 is also known to work.

- If you want to build man pages, you'll also need [pandoc](https://pandoc.org/).

First, get the latest sources and configure the project:

```bash
git clone https://gitlab.com/oldnomad/picosocks5
cd picosocks5
autoreconf -f -i -Wall
./configure
```

Next, build and install the daemon:

```bash
make && sudo make install
```

# Using PicoSOCKS5

```bash
picosocks5 -u nobody -g nogroup -a authfile.txt "*:1080"
```

For more information on running PicoSOCKS5 see file
[src/picosocks5.md](src/picosocks5.md) or man page for _picosocks5_(8).
Short summary of options is also available from command line:

```bash
picosocks5 --help
```

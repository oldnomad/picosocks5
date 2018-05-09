# What is it?

PicoSOCKS5 is a SOCKS5 proxy cobbled together in less than 5 days of lazy coding.
It is written in pure C and uses no extra libraries besides GLibC. Within GLibC
it uses only following GNU extensions to POSIX.1-2017 + XSI:

- vsyslog(3).
- Format specifier "%m" in printf.

# License

PicoSOCKS5 is licensed under GNU Generat Public License Version 3 (GPLv3).
For full text of the license see file [LICENSE.txt](LICENSE.txt) in the root
of the project.

# Supported features

- PicoSOCKS5 implements SOCKS5 ([RFC 1928](https://www.ietf.org/rfc/rfc1928.txt)).
  The only request type currently implemented is CONNECT, but other request types
  may be implemented later. Earlier versions of SOCKS (SOCKS4, SOCKS4a) are not
  implemented. Update [draft](https://www.ietf.org/archive/id/draft-ietf-aft-socks-pro-v5-05.txt)
  is not implemented.
- PicoSOCKS5 implements username/password authentication for SOCKS5
  ([RFC 1929](https://www.ietf.org/rfc/rfc1929.txt)). Usernames and passwords for
  authentication are read from a file in format compatible with Apache htpasswd.
- PicoSOCKS5 supports incoming and outgoing connections both in IPv4 and IPv6.
  In particular, it can accept requests to connect to IPv6 servers from IPv4 clients,
  and vice versa.

# Known disadvantages

- PicoSOCKS5 has no limits on incoming connections, so it can be easily overwhelmed by
  a deliberate denial-of-service attack.
- There's no access control (any client can connect to any server).
- There's currently no support for more secure authentication methods, like GSS-API
  ([RFC 1961](https://www.ietf.org/rfc/rfc1961.txt)) or CHAP
  ([draft](https://www.ietf.org/archive/id/draft-ietf-aft-socks-chap-01.txt)). These
  may be added later.
- There's currently no support for SOCKS-over-SSL
  ([draft](https://www.ietf.org/archive/id/draft-ietf-aft-socks-ssl-00.txt)).
  I'll be grateful for any pointers about existing implementations of this
  protocol variant.

# Building PicoSOCKS5

```bash
git clone https://github.com/oldnomad/picosocks5.git
cd picosocks5
./configure
make && make install
```

# Using PicoSOCKS5

```bash
picosocks5 -u nobody -g nobody "*:1080"
```

For more information on running PicoSOCKS5:

```bash
picosocks5 --help
```

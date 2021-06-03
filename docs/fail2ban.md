# Using Fail2Ban to protect PicoSOCKS5

Since PicoSOCKS5 is not designed for high loads, it may be beneficial
to protect it using a Fail2Ban rule.

The filter below detects malformed SOCKS5 offer, which usually indicates
confused clients expecting some other service on this port:

```ini
# Fail2Ban filter PicoSOCKS5 malformed offer
#

[INCLUDES]

before = common.conf

[Definition]

_daemon = (?:picosocks5)

prefregex = ^%(__prefix_line)s<F-CONTENT>.+</F-CONTENT>$

failregex = ^<<HOST>:\d+\|OFFER> Malformed initial offer:\s.*$

ignoreregex = 

journalmatch = _SYSTEMD_UNIT=picosocks5.service
```

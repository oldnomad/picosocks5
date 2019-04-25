% PIS5USER(1) | Lightweight SOCKS5 Daemon

# NAME

**pis5user** - generate secrets for **picosocks5**, lightweight SOCKS5 daemon

# SYNOPSIS

| **pis5user** \[_options_...] _user_

# DESCRIPTION

The **pis5user**(1) command generates authentication secrets for user _user_.
These secrets can be added to an authentication file to use with
**picosocks5**(8) daemon.

# OPTIONS

`-m` _auth-method-list_, `--method` _auth-method-list_
:   Specify a comma-separated list of authentication methods to generate
    secrets for. Default is to generate secrets for all methods supported
    by **picosocks5**(8).

`-h`, `--help`
:   Print short help message and exit.

# SEE ALSO

_picosocks5_(8)

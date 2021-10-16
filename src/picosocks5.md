% PICOSOCKS5(8) | Lightweight SOCKS5 Daemon

# NAME

**picosocks5** - lightweight SOCKS5 daemon

# SYNOPSIS

| **picosocks5** \[_options_...] \[_listen-address_\[:_listen-port_]]

# DESCRIPTION

The **picosocks5(8)** command starts a SOCKS5 daemon with configuration
specified on the command line or in a configuration file given in command
line option **-\-config**.

Note that all command line parameters are processed in order in which
they appear on command line, so parameters specified later will, as a
rule, override earlier ones. Exceptions to this rule are options
**-\-config** and **-\-auth**.

The only non-option command line parameter specifies address and port
at which the daemon will listen for client connections. This parameter
consists of address and port, separated by colon. If address is omitted
(empty string), it is equivalent to specifying address `"*"` (see below).
If port is omitted, together with the separating colon, port `1080` is used.
Thus, omitting the listen specification altogether is equivalent to
listen specification `"*:1080"`.

Listen address can be any of following:

  * IPv4 address in any format supported by **inet_aton**(3).
  * IPv6 address, enclosed in square brackets, in any format supported by
    **inet_pton**(3).
  * A hostname resolving to any set of IPv4 and IPv6 addresses.
  * Asterisk (`"*"`), interpreted as a wildcard address.

Listen port can be a decimal number of a service name (see **services**(5)).

# OPTIONS

`-c` _config-file_,  `--config` _config-file_
:   Specify configuration file. See below for file format. Any number of
    configuration files can be loaded. Configuration file specified in
    this option may override effect of options and configuration files
    specified earlier.

`-a` [_auth-format_:]_auth-spec_, `--auth` [_auth-format_:]_auth-spec_
:   Specify authentication source. If _auth-format_ is omitted, default
    format is `"password"`. Any number of authentication sources can be
    loaded. Note that order in which authentication sources are specified
    may affect successful authentication if there is more than one secret
    per user.

`-A`, `--anonymous`
:   Allow anonymous access even if there are users in the authentication
    sources.

`-B` _bind-address_, `--bind` _bind-address_
:   Specify external address to use for *BIND* and *UDP ASSOCIATE* commands.
    Address can be an IPv4 address, an IPv6 address, or a host name
    resolving to any set of IPv4 and IPv6 addresses. If program is compiled
    with **getifaddrs**(3) support, bind address can be also specified as
    an interface name with prefix "@" (for example, "@eth0"), in which case
    addresses of specified interface (one for each address family) will be
    used.

    Note that only the last specified address for each address family will
    be used.

    By default no external addresses are specified, so commands requiring
    them are disabled.

`--maxconn` _number_
:   Specify maximum number of concurrent client connections, or zero for
    no limit. Default is 0 (no limit).

`--timeout` _float-number_
:   Specify read/write timeout (in seconds) for all connections, or zero
    for no limit. Default is 0 (no limit). Maximum timeout is 3600 seconds
    (one hour), any value higher than that will be interpreted as 3600.

`--network` [!]_address_[/_bits_],...
:   Specify rules allowing and disallowing IPv4 or IPv6 networks for
    incoming client connections.

    Note that rules are processed in order until the first match, so if
    a subnetwork has to be excluded from a larger allowed network,
    disallow rule should precede allow rule.

    By default all addresses are allowed. However, if at least one rule
    (allow or disallow) is specified, an address is allowed only if it
    has a matching allow rule.

`--request` [!]_method_[:_address_[/_bits_]],...
:   Specify rules allowing and disallowing specific types of requests,
    optionally limited to destination network.

    Supported method prefixes are `"connect"`, `"bind"`, `"assoc"`,
    and `"all"` for all types of requests.

    Omitted network specification, or, alternatively, specifying the
    network as "*", means that the rule is applied to requests to any
    destination.

    Note that rules are processed in order until the first match, so if
    a subset of requests has to be excluded from a larger allowed set,
    disallow rule should precede allow rule.

    By default all requests are allowed (equivalent to rule "all:*").
    However, if at least one rule (allow or disallow) is specified,
    a request is allowed only if it has a matching allow rule.

`-u` _user_, `--user` _user_
:   Drop privileges to specified user. User can be a user name or
    a numeric UID.

`-g` _group_, `--group` _group_
:   Drop privileges to specified group. Group can be a group name or
    a numeric GID.

`--nofork`
:   Do not fork to background. Also, the default logging mode after this
    option is `"stderr"`, unless specified otherwise.

`-L` _log-mode_, `--logmode` _log-mode_
:   Set log mode. Supported modes are `"syslog"` (default), `"stderr"` and
    `"combined"` (logging both to **syslog**(3) and **stderr**(3)).

`-v` _log-level_, `--loglevel` _log-level_
:   Set log verbosity level. Supported levels are: `"err"`, `"warn"`,
    `"notice"`, `"info"`, `"debug"`, and `"none"`.

`-h`, `--help`
:   Print short help message and exit.

`-V`, `--version`
:   Print program version and exit.

## Note on effects of -\-nofork

Option **-\-nofork** instructs the daemon to stay in foreground, but it also
has several side-effects:

  * Signals `SIGHUP` and `SIGPIPE` are not ignored.
  * Privileges are not dropped, even if **-\-user** and **-\-group**
    are specified.
  * If **-\-logmode** is not specified, default log mode is not `"syslog"`,
    but `"stderr"`.

Note also that if parent PID is 1, **-\-nofork** is the default.

## Note on -\-user and -\-group

Privileges are not dropped if the daemon is not started by a superuser,
if parent PID is 1 (**init**(1)), or if **-\-nofork** is specified.

## Note on IPv4 and IPv6 addresses

This program uses **getaddrinfo**(3) for host and network address
parsing. As a result, in all places where an address is expected,
following forms are accepted:

  * A host name resolving to IPv4 and/or IPv6 addresses.
  * Full decimal representation of IPv4 address (four dot-separated
    decimal numbers).
  * Any representation of IPv6 address.

Alternative forms of IPv4 addresses (octal, hexadecimal, with fewer than four
dot-separated elements) are not accepted.

## Note on ACL network specification

For internal reasons, a network with empty mask (0 bits) will be matched
both by IPv4 and IPv6 addresses, regardless of address family of the network
address.

# CONFIGURATION FILE

Configuration file is a text file, in common "INI-like" format.
Empty lines are ignored. Leading and trailing whitespace in a line is ignored.
Lines starting with `"#"` or `";"` character are ignored.

Any non-ignored line is either a section header (a section title
enclosed in brackets), or parameter name and parameter value separated
by `"="` character. Whitespace around the separator is ignored.
There is no quoting or escaping for parameter values, parameter names,
or section names.

For most configuration parameters, parameter name is the same as
corresponding command line option, without the `"--"` prefix.
Exceptions are:

  * Command line options **-\-help** and **-\-version** have no
    corresponding configuration parameters.
  * Configuration parameter **include** corresponds to command
    line option **-\-config**; that is, once this configuration
    parameter is encountered, a configuration file specified in
    it is immediately parsed before proceeding to the next
    configuration parameter in this file.
  * Configuration parameter **listen** corresponds to command
    line positional parameter (listen specification).

Parameter values correspond to values specified for options. Values for
boolean options (**-\-anonymous** and **-\-nofork**) are interpreted as
boolean values, with `"yes"`, `"true"`, and `"1"` interpreted as a true
value, and any other value as a false value.

## ACL sections

Configuration file may contain named sections. These sections specify
ACL sets for corresponding groups of users. That is, a section heading
`[name]` starts a section with parameters for users in group `"name"`.

Section headers may repeat. All parameters between section header `[name]`
and the next section header (or end of file) belong to section `[name]`.

ACL set section may include following parameters:

  * Configuration parameter **request**, containing rules allowing
    and disallowing specific types of requests. See command line
    option **-\-request** for explanation.
  * Configuration parameter **network**, containing rules allowing
    and disallowing IPv4 or IPv6 networks. See command line option
    **-\-network** for explanation.
  * Configuration parameter **base**, specifying name of parent
    ACL set section. Rules from the parent section will be checked
    after rules specified in this section. If parent section is
    not specified, root (global) section is used.

Note that rules in the ACL set section are checked only after SOCKS
authentication. That means that an incoming connection from an
address forbidden in an ACL set will be accepted, authenticated,
and only after that dropped. The only exception from this rule
is default ACL set `[*]` (see below).

Special ACL set section with header `[*]`, if specified, will be
used for anonymous users and for users without a group. It will
not, however, be applied to users with a group for which no ACL
set section was specified. If this section contains parameter
**network**, clients coming from networks not allowed by this
parameter will be denied anonymous access on authentication method
negotiation stage.

# AUTHENTICATION SOURCES

One or more authentication sources can be specified in the parameters
or in configuration files. Sources are processed in order in which they
appear. No checks for duplicates are performed.

Authentication sources are initialized before dropping privileges, so,
depending on the implementation, they may be readable only to the user
invoking the daemon. They may be inaccessible to effective user and
group specified in **-\-user** and **-\-group** options.

Currently the only format supported for authentication sources is
`"password"`.

## Password file format

**NOTE:** File format `"password"` _changed_ between versions 0.2 and
0.3. Password files from version 0.2 will be accepted with warnings,
but this support may be dropped in future versions.

Authentication source in format `"password"` is a text file with each line
containing colon-separated fields. No empty lines or comments are allowed.

Each line must contain 3 fields containing:

  * User name, or an empty field for server-side secret.
  * Group name, or an empty field for no group.
  * Secret in one of supported formats.

As an exception, lines in old (0.2) format with only 2 fields are accepted.
In this case, the second field contains the secret, and the group name is
always empty. A warning will be issued for each line in old format.

Supported secret formats are Base64-encoded plain password (with prefix
`"$base64$"`), or **crypt(3)**-compatible hash value. All versions of
_glibc_ support MD5-crypt (prefix `"$1$"`), as produced, for example,
by command **openssl passwd -1**. Recent versions of _glibc_ also support
SHA-256 (prefix `"$5$"`) and SHA-512 (prefix `"$6$"`). Some distributions
include an extension supporting Blowfish (prefix `"$2a$"`).

If several secrets are provided for the same user name, authentication will
use the first secret in format acceptable for the authentication method
(see below). For example, if the password file contains for a user both a
**crypt(3)**-compatible hash and a plain Base64-encoded password (in that
order), basic authentication method will use **crypt(3)**-compatible hash
(because it comes first), but CHAP authentication method will use plain
password.

### Basic authentication method

Basic authentication method can use both **crypt(3)**-compatible hash,
or plain password, whichever comes first.

### CHAP authentication method

CHAP authentication method can use only plain password.

# SEE ALSO

_pis5user_(1)

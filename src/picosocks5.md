% PICOSOCKS5(8) | Lightweight SOCKS5 Daemon

# NAME

**picosocks5** - lightweight SOCKS5 daemon

# SYNOPSIS

| **picosocks5** \[_options_...] \[_listen-address_\[:_listen-port_]]

# DESCRIPTION

The **picosocks5(8)** command starts a SOCKS5 daemon with configuration
specified on the command line or in configuration file given in command
line option **--config**.

Note that all command line parameters are processed in order in which
they appera on command line, so parameters specified later will, as a
ruke, override earlier ones. Exceptions to this rule are options
**--config** and **--auth**.

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

`-a` [_auth-format_:]_auth-file_, `--auth` [_auth-format_:]_auth-file_
:   Specify authentication file. If _auth-format_ is omitted, default format
    is `"password"`. Any number of authentication files can be loaded.
    Note that order in which authentication files are specified may
    affect successful authentication if there is more than one secret
    per user and method pair.

`-A`, `--anonymous`
:   Allow amomymous access even if there are users in the authentication
    files.

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

## Note on effects of --nofork

Option **--nofork** instructs the daemon to stay in foreground, but it also
has several side-effects:

  * Singals `SIGHUP` and `SIGPIPE` are not ignored.
  * Privileges are not dropped, even if **--user** and **--group**
    are specified.
  * If **--logmode** is not specified, default log mode is not `"syslog"`,
    but `"stderr"`.

Note also that if parent PID is 1, **--nofork** is the default.

## Note on --user and --group

Privileges are not dropped if the daemon is not started by a superuser,
if parent PID is 1 (**init**(1)) or if **--nofork** is specified.

# CONFIGURATION FILE

Configuration file is a text file, each line of which can be either empty,
or a line comment introduced by `"#"` character, or parameter name and
parameter value separated by `"="` character. Leading and trailing
whitespace is eliminated, but no whitespace is allowed around the
separator. There is no quoting or escaping for either parameter values
or parameter names.

Parameter names correspond to long names of options, without the `"--"`
prefix. Options **--config**, **--help**, and **--version** are
not allowed as configuration file parameters.

Additional parameter name, **listen**, corresponds to listen specification
(non-option command line parameter).

Parameter values correspond to values specified for options. Values for
boolean options (**--anonymous** and **--nofork**) are interpreted as
boolean values, with `"yes"`, `"true"`, and `"1"` interpreted as a true
value, and any other value as a false value.

# AUTHENTICATION FILES

One or more authentication files can be specified in the parameters or in
configuration files. Files are processed in order in which they appear.
No checks for duplicates are performed, and all parsed authentication data
is kept in memory.

Authentication files are read before dropping privileges, so they need to
be readable only to the user invoking the daemon. They may be inaccessible
to effective user and group specified in **--user** and **--group**
options.

Currently the only format supported for authentication files is `"password"`.

## Password file format

**NOTE:** File format `"password"` _changed_ between versions 0.2 and
0.3. Authentication files from version 0.2 will be accepted with warnings,
but this support may be dropped in future versions.

Authentication file in format `"password"` is a text file with each line
containing colon-separated fields. No empty lines or comments are allowed.

Each line must contain 3 fields containing:

  * User name, or an empty field for server-side secret.
  * Authentication method. Currently methods `basic` and `chap` are supported.
    Empty field is interpreted as `basic`.
  * Method-dependent secret.

As an exception, lines in old (0.2) format with only 2 fields are accepted.
In this case, the second field contains the secret, and the method is always
`"basic"`. A warning will be issued for each line in old format.

Note that if you want a user to be able to be authenticated by any method,
you'll have to include separate lines for each authentication method.

### Basic authentication method

For authentication method `"basic"`, the secret is a password hash in
a salted format supported by **crypt**(3) function. All versions of _glibc_
support MD5-crypt (prefix `"$1$"`), as produced, for example, by command
**openssl passwd -1**. Recent versions of _glibc_ also support SHA-256
(prefix `"$5$"`) and SHA-512 (prefix `"$6$"`). Some distributions include
an extension supporting Blowfish (prefix `"$2a$"`).

### CHAP authentication method

For authentication method `"chap"`, the secret is base64-encoded and
prefixed with text `"$base64$"`.

# SEE ALSO

_pis5user_(1)
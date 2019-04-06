# Command line parameters

All configuration for PicoSOCKS5 is specified in command line, or in a
configuration file specified in command line option `--config`. There is no
default confifuration file.

The only non-option parameter of PicoSOCKS5 is listen address. Listen address
consists of host address and port, separated by colon ("`:`").

  * Host address can be an IPv4 address, an IPv6 address (in square brackets),
    a host name, or, as a special case, an asterisk character ("`*`") meaning
    all local addresses (that is, IPv4 address `0.0.0.0` and IPv6 address
    `[::]`). Host address may also be omitted, having the same effect as an
    asterisk.
  * Port can be specified either as a port name, or as a decimal port number.
    If port is omitted (together with the separating colon), default port
    number 1080 is used.
  * If the parameter is omitted altogether, default value is `*:1080`.

Options recognized by PicoSOCKS5 are:

|Option|Long option  |Parameter              |Description |
|:---- |:----------- |:--------------------- |:---------- |
|`-c`  |`--config`   |*config-file*          | Configuration file. See below for file format. |
|`-a`  |`--auth`     |[*format*:]*auth-file* | Authentication file. If format is  omitted, default format is `password`. |
|`-A`  |`--anonymous`|                       | Allow amomymous access even if there are users in the authentication file. |
|`-u`  |`--user`     |*user*                 | Drop privileges to specified user. User can be a user name or a numeric UID. |
|`-g`  |`--group`    |*group*                | Drop privileges to specified group. Group can be a group name or a numeric GID. |
|      |`--nofork`   |                       | Do not fork to background. This also changes default logging mode (see below). |
|`-L`  |`--logmode`  |*log-mode*             | Set log mode. Supported modes are `syslog` (default), `stderr` and `combined`. |
|`-v`  |`--loglevel` |*log-level*            | Set log verbosity level. Supported levels are: `err`, `warn`, `notice`, `info`, `debug`, and `none`. |
|`-h`  |`--help`     |                       | Print short help message and exit. |
|`-V`  |`--version`  |                       | Print program version and exit. |

## Note on effects of --nofork

Option `--nofork` instructs PicoSOCKS5 to stay in foreground, but it also
has several side-effects:

  * Singals `SIGHUP` and `SIGPIPE` are not ignored.
  * Privileges are not dropped, even if `--user` and `--group` are specified.
  * If `--logmode` is not specified, default log mode is not `syslog`, but `stderr`.

Note also that if parent PID is 1, `--nofork` is the default.

## Note on --user and --group

Privileges are not dropped if invoking user is not root or if `--nofork` is specified.

# Configuration file

One or more configuration files can be given in the parameters. Files are processed
in the order in which they appear. For all options except `--config` and `--auth`
value specified later in the command line, either as an option or as a value in a
configuration file, overrides all previous values.

Configuration file is a text file, each line of which can be either empty, or a
line comment introduced by "`#`" character, or parameter name and parameter value
separated by "`=`" character. Leading and trailing whitespace is eliminated, but no
whitespace is allowed around the separator. There is no quoting or escaping for
either parameter values or parameter names.

Parameter names correspond to long names of options, without the `--` prefix.
Options `--config`, `--help`, and `--version` are not allowed as configuration
file parameters.

Additional parameter name, `listen`, corresponds to listen address (non-option
parameter on the command line).

Parameter values correspond to values specified for corresponding options.
Values for boolean options (`--anonymous` and `--nofork`) are interpreted as
boolean values, with `yes`, `true`, and `1` interpreted as a true value, and
every other value as a false value.

# Authentication files

One or more authentication files can be given in the parameters. Files are processed
in order in which they appear. No checks for duplicates are performed, and all
parsed authentication data is kept in memory.

Authentication files are read before dropping privileges, so they need to be readable
only to the user invoking the program. They may be inaccessible to effective user and
group specified in `--user` and `--group` options.

Depending on the authentication method, authentication secrets (passwords or keys)
can be open (e.g. salted password hashes) or sealed. To decrypt sealed secrets, a
key can be specified in the parameters. Note that secrets are unsealed only when
they are needed, and currently there is no way to specify different decrypting
keys for different secrets.

Currently the only format supported for authentication files is `password`.

## Password file format

**NOTE:** File format `password` **_changed_** between versions 0.2 and 0.3.
Authentication files from version 0.2 will be accepted with warnings, but
this support may be dropped in future versions.

Authentication file in format `password` is a text file with each line
containing colon-separated fields. No empty lines or comments are allowed.

Each line must contain 3 fields containing:

  * User name, or an empty field for server-side secret.
  * Authentication method. Currently methods `basic` and `chap` are supported.
    Empty field is interpreted as `basic`.
  * Method-dependent secret.

As an exception, lines in old (0.2) format with only 2 fields are accepted.
In this case, the second field contains the secret, and the method is always
`basic`. A warning will be issued for each line in old format.

Note that if you want a user to be able to be authenticated by any method,
you'll have to include separate lines for each authentication method.

### Basic authentication method

For authentication method `basic`, the secret is a password hash in a salted
format supported by `crypt(3)` function. All versions of GLibc support
MD5-crypt (prefix `$1$`), as produced, for example, by command `openssl passwd -1`.
Recent versions of GLibc also support SHA-256 (prefix `$5$`) and SHA-512
(prefix `$6$`). Some distributions include an extension supporting
Blowfish (prefix `$2a$`).

### CHAP authentication method

For authentication method `chap`, the secret is a base64-encoded and
prefixed with text `$base64$`.

### Utility `pis5user`

PicoSOCKS5 includes a utility, called `pis5user`, to help generate secrets
for a `password`-format file. Utility generates secrets lines for specified
user for all supported authentication methods.

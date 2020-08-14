This is a design plan for ACLs in picosocks5.

  - Since our configuration format is simple INI, ACL description
    should fit INI-style sections.
  - ACL may limit:
    - Allowed client IP addresses (late check).
    - Allowed authentication.
    - Allowed SOCKS5 methods and server IP addresses.
  - We won't go extra mile just to satisfy complex setups. There's
    no need for Turing-complete solutions.

# Cases to support

  - Default: no limitations.
  - Trivial: limit client IP addresses, limit methods, all clients
    are equal.
  - SME: limit client IP addresses, clients separated into groups,
    each group having its own limits on methods.

# Proposed implementation

  - [x] Parameter `network` for connection-time client address check.
  - [ ] Parameter `request` for limiting supported request operations.
        Parameter value is a comma-separated list of request patterns.
        Each pattern consists of request type prefix (`connect`, `bind`,
        `associate`, or `all` for all types), a colon (`:`), and a
        network or domain name pattern. If omitted, `all:*` (all types,
        all destinations) is used. Some aliases are allowed
        (`assoc` = `associate`).
  - [ ] Parameter `auth-method` for limiting supported authentication
        methods. Parameter value is a comma-separated list of authentication
        methods (`anonymous`, `basic`, or `chap`); or `none` for no methods;
        or `all` for all methods. If omitted, `all` (all methods) is used.
        Some aliases are allowed (`anon` = `anonymous`).
  - [ ] Allow named sections ("group parameters") containing:
    - [ ] Parameters `network`, `request`, and `auth-method`.
    - [ ] Parameter `include`, referring to other named sections.
  - [ ] Parameter `default-group` to specify group parameters for
        anonymous users and users without a group.
  - [ ] Format of password files is extended to allow specifying
        group name in the second field.

Thus, there's a tree of group parameter sets, with each node
containing:

  - Group name (mandatory, except root).
  - Optional reference to parent group.
  - Optional list of allowed and disallowed client networks.
  - Optional list of allowed request patterns.
  - Optional array of allowed authentication methods.

**NOTE:** Parameter `network` specified in the main section
is applied before the group parameters. For example, if a
network is disallowed in the main section, connections from
it won't be accepted even if it's allowed in the group.
On the other hand, if a request is disallowed in the
main section, it can still be allowed in a group.

# Changes in algorithms

On authentication method negotiation stage:

  - Offer all available authentication methods, since we
    don't know the group yet.
  - Check the default group: 
    - If client address is not in the default group networks,
      don't offer anonymous authentication method.

On user being known completion:

  - Determine user group and set it for the connection.
  - Deny if currently used authentication method is not allowed.
  - Deny if client address is not allowed.
  - Deny if all request types are disallowed.

On request:

  - Deny if request type is not allowed.

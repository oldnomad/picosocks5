# Features to implement

## SOCKS-over-SSL

  - [ ] Support for tunnelling auth methods (SOCKS-over-SSL et al).
  - [ ] Support for sub-negotiation in tunnelling auth methods.
  - [ ] SOCKS-over-SSL.

## Protocol features

  - [x] BIND.
  - [ ] UDP ASSOCIATE and datagram relaying.
    - [ ] UDP datagram relaying.
    - [ ] Limit access to UDP relaying (needs ACL).

## General improvements

  - [x] Limits and timeouts on connections.
    - [x] Limit on number of concurrent connections.
    - [x] Timeout for idle connections.
  - [x] Configuration file.
  - [x] ACL.
    - [x] Limit incoming addresses.
    - [x] Limit request types.
    - [x] Limit operations for specific users.

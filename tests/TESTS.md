# Test coverage

Currently tests cover only minor (but tricky) parts of the appluication.
Coverage will be improved in time.

## Prerequisites

Tests use [Cmocka](https://cmocka.org/) C testing framework. If Cmocka
is not installed, tests will be skipped.

If [LCov](https://github.com/linux-test-project/lcov) is installed,
tests will collect coverage information. Coverage report can be
generated from project top directory using command `make coverage`.
Coverage report in HTML format will be generated in subdirectory
`coverage/`.

## Individual tests

### Tests for crypto implementation

- `test_random`: Only tests that random data can be generated.
  It doesn't test randomness quality.
- `test_hmac_md5`: Tests HMAC-MD5 on examples from RFC 2202.
  Border conditions and exceptions are not tested.

### Tests for utility functions

- `test_parse`: Tests parsing user/group. This test presumes
  that user `root` and group `root` both exist and have
  UID 0 and GID 0, respectively.
- `test_decode_addr`: Tests converting socket address and
  network to textual form. Note that this conversion is used
  only for logging.
- `test_base64`: Tests Base64 (RFC 4648) encoding and decoding,
  using examples from the RFC. Border conditions and exceptions
  are not tested.

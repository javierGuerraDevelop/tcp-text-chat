# NON-PRODUCTION loopback TLS fixtures

Every certificate and private key in this directory is a **NON-PRODUCTION**
loopback test fixture only. Never deploy them, install their CAs as trusted roots,
or reuse them outside isolated tests.

- `trusted_ca.crt`: trusted test root, valid from 2020-01-01 to 2040-01-01.
- `untrusted_ca.crt`: independent untrusted test root with the same validity.
- `trusted_server.crt` / `.key`: trusted-CA server certificate for `localhost`,
  `127.0.0.1`, and `::1`.
- `wrong_host_server.crt` / `.key`: trusted-CA server certificate for
  `chat.invalid` only.
- `untrusted_server.crt` / `.key`: untrusted-CA server certificate for
  `localhost`, `127.0.0.1`, and `::1`.
- `expired_server.crt` / `.key`: trusted-CA server certificate for the usual
  loopback names, valid only from 2020-01-01 to 2021-01-01.

Each `.key` is the unencrypted RSA-2048 private key for the same-named `.crt`.
The non-expired leaves are valid from 2020-01-01 to 2040-01-01. All leaves have
`CA:FALSE`, subject and authority key identifiers, key usage, and `serverAuth`
extended key usage. CA private keys are intentionally not retained.

Regenerate all identities with `/usr/bin/openssl` (no network access):

```sh
cd tests/tls_fixtures
./generate.sh
```

The script replaces every fixture certificate and key. Validity dates, serials,
subjects, and extensions are fixed; each run generates fresh independent keys.

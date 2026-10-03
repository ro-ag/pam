# TLS test fixtures — not for production

Static certificates for `pam_net`'s TLS origin fixture
(`pam_net::testing::TlsOrigin`, an `openssl s_server -www` on a loopback port).
Every subject carries `O=PAM test fixtures - not for production`. The private
key here protects nothing: it only lets the test server prove that the
launcher's CA-bundle setting is what makes a private issuer trusted.

| File | What it is |
| --- | --- |
| `ca.pem` | The test CA (`CN=PAM Test Inspection CA`), valid to 2051. The bundle a test trusts. Its private key was discarded after signing. |
| `other-ca.pem` | An unrelated CA (`CN=PAM Test Unrelated CA`) that issued nothing. The bundle that must not work. |
| `leaf.pem` | Issued by `ca.pem` for `origin.pam-test.invalid`, `localhost` and `127.0.0.1`, valid to 2051. |
| `wrong-name.pem` | Issued by `ca.pem` for `other.pam-test.invalid` only. |
| `expired.pem` | Issued by `ca.pem` for the same names as `leaf.pem`, valid 2020-01-01 to 2020-02-01. |
| `leaf.key` | The one EC P-256 key behind all three leaves. Test-only; committed on purpose. |

Generated once, 2026-10-02, with OpenSSL 3.6 (`-not_before`/`-not_after`
need OpenSSL 3.4 or newer); nothing regenerates them automatically. To
regenerate the whole set:

```sh
O=openssl
$O ecparam -name prime256v1 -genkey -noout -out ca.key
$O req -x509 -new -key ca.key -sha256 -days 9125 \
  -subj "/O=PAM test fixtures - not for production/CN=PAM Test Inspection CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
$O ecparam -name prime256v1 -genkey -noout -out other-ca.key
$O req -x509 -new -key other-ca.key -sha256 -days 9125 \
  -subj "/O=PAM test fixtures - not for production/CN=PAM Test Unrelated CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out other-ca.pem
$O ecparam -name prime256v1 -genkey -noout -out leaf.key
leaf() { # <name> <cn> <san> <validity args…>
  $O req -new -key leaf.key -subj "/O=PAM test fixtures - not for production/CN=$2" -out $1.csr
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > $1.ext
  $O x509 -req -in $1.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -extfile $1.ext "${@:4}" -out $1.pem
  rm $1.csr $1.ext
}
leaf leaf       origin.pam-test.invalid "DNS:origin.pam-test.invalid,DNS:localhost,IP:127.0.0.1" -days 9125
leaf wrong-name other.pam-test.invalid  "DNS:other.pam-test.invalid" -days 9125
leaf expired    origin.pam-test.invalid "DNS:origin.pam-test.invalid,DNS:localhost,IP:127.0.0.1" \
  -not_before 20200101000000Z -not_after 20200201000000Z
rm ca.key other-ca.key ca.srl
```

The tests that use these are skipped with a printed line when no `openssl`
is available (`PAM_TEST_OPENSSL`, then `/usr/bin/openssl` on macOS, then
`PATH`), unless `PAM_REQUIRE_TLS_FIXTURE=1` makes absence a failure.

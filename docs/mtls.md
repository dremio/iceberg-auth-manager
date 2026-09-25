<!--
Copyright (C) 2025 Dremio Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# Dremio AuthManager for Apache Iceberg - Mutual TLS (RFC 8705)

## Overview

The Dremio AuthManager for Apache Iceberg supports
[RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705).

RFC 8705 is heavily favored in regulated finance, healthcare, and FAPI-conformant deployments
where the client TLS cert is already provisioned via the organization's PKI.

RFC 8705 has two halves:

* **§2 Mutual-TLS client authentication.** The client proves its identity to the authorization
  server by presenting an X.509 certificate during the TLS handshake on the token endpoint —
  instead of sending a `client_secret`, a `client_secret_jwt`, or a `private_key_jwt`. Two flavors
  are defined:
  * `tls_client_auth` — the certificate is validated against a configured PKI trust anchor (CA) and
    the AS matches the cert's subject DN / SAN against the registered client.
  * `self_signed_tls_client_auth` — the certificate is self-signed and the AS matches its
    SHA-256 thumbprint against the value registered with the client.
* **§3 Certificate-bound access tokens.** When the AS issues a token to an mTLS-authenticated
  client, it embeds the SHA-256 thumbprint of the client cert in a `cnf.x5t#S256` confirmation
  claim. The resource server then verifies on every call that the TLS cert presented to it has
  the same thumbprint — preventing token replay by a thief who lacks the private key.

The auth manager implements the first half of RFC 8705, that is, Mutual-TLS client authentication.
The other half (Certificate-bound access tokens) falls under the responsibility of the resource
server.

## Quick Start

Configure the auth manager with a TLS client authentication method and point the HTTP client at a
PKCS#12 key store containing the client cert and private key:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

rest.auth.oauth2.issuer-url=https://idp.example.com/realms/main
rest.auth.oauth2.grant-type=client_credentials
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-auth=tls_client_auth
rest.auth.oauth2.scope=catalog

# Use the Apache HTTP client (the default URLConnection-based client does not honor these settings).
rest.auth.oauth2.http.client-type=APACHE
rest.auth.oauth2.http.ssl.key-store.path=/etc/iceberg/client.p12
rest.auth.oauth2.http.ssl.key-store.password=changeit
# Optional: pick a specific entry from the keystore.
# rest.auth.oauth2.http.ssl.key-store.alias=client
```

With this configuration the auth manager:

1. Loads the PKCS#12 keystore once at startup, sets up an `SSLContext` with the client cert
   and private key, and uses it for every TLS handshake to the token endpoint.
2. Sends the token request with `client_id` in the form body and no `client_secret` — the TLS
   handshake itself is the proof of identity (RFC 8705 §2.1.2).
3. If the AS issues a certificate-bound access token, the auth manager passes it through unchanged;
   the resource server is responsible for enforcing the `cnf.x5t#S256` binding.

For `self_signed_tls_client_auth`, change `client-auth=self_signed_tls_client_auth`. The keystore
configuration is identical; the AS just validates the cert differently.

## Key Store Format

Only the platform-default key store format (PKCS#12 on modern JREs) is accepted. If you only have
PEM files, convert with one `openssl` command:

```shell
openssl pkcs12 -export \
  -in client-cert.pem \
  -inkey client-key.pem \
  -out client.p12 \
  -name client
```

PEM-only configuration is not supported because the production code path is required to work
without BouncyCastle (PKCS#1 and SEC 1 PEM formats need BC to parse). Using PKCS#12 keeps the
runtime BouncyCastle-free.

## Certificate-Bound Tokens (RFC 8705 §3): What You Must Configure on the REST Catalog

**The auth manager only controls the HTTP client that talks to the authorization server's token
endpoint.** Catalog REST traffic — every call to `GET /v1/catalogs/...`, `POST /v1/tables/...`,
etc. — goes through Iceberg's own `HTTPClient`, which is configured **separately** through Iceberg's
catalog properties.

For certificate-bound tokens to actually work end-to-end:

1. Configure the auth manager with `client-auth=tls_client_auth` or `self_signed_tls_client_auth`
   and a keystore (as above). The AS will issue a token with `cnf.x5t#S256` bound to that cert.
2. **Configure Iceberg's REST catalog HTTPS client with the same client certificate.** Refer to
   the Iceberg `RESTCatalog` documentation for the relevant HTTPS / keystore properties. If the
   Iceberg HTTP client uses a different cert (or no cert), the resource server will reject every
   request with `invalid_token` because the TLS cert thumbprint won't match the token's `cnf`
   claim.

## Validation and Constraints

* When `client-auth` is `tls_client_auth` or `self_signed_tls_client_auth`,
  `rest.auth.oauth2.http.ssl.key-store.path` **must** be set — startup fails fast otherwise.
* When one of the TLS methods is in use, `rest.auth.oauth2.client-secret` **must not** be set —
  there is no shared secret in this auth method, and a stray value would mask a misconfiguration.
* The keystore path must be readable; the alias, if specified, must exist in the keystore.

## Interaction with DPoP

mTLS and DPoP are two independent mechanisms for the same goal: sender-constrained access tokens.
You typically pick one or the other based on what your AS supports and what your deployment
already provisions. The auth manager allows both to be enabled simultaneously, but most AS only
honor one binding per token — check your AS's documentation.

## Full Configuration Reference

See the [Configuration](./configuration.md#http-client-settings) section for the keystore
properties, and the [client-authentication](./client-authentication.md) page for the full list of
supported client authentication methods.

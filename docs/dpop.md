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
# Dremio AuthManager for Apache Iceberg - DPoP (Demonstrating Proof of Possession)

## Overview

The Dremio AuthManager for Apache Iceberg supports
[RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449).

DPoP binds an access token to an asymmetric keypair held by the client. Every request carries a
short-lived, signed JWT ("DPoP proof") whose public key matches the one the access token was issued
for. Therefore, a stolen access token cannot be replayed by an attacker who does not also possess 
the private key.

When DPoP is enabled, the AuthManager:

* Generates an ephemeral asymmetric keypair on startup.
* Attaches a `DPoP` header carrying a signed proof JWT to every request sent to the authorization
  server's token endpoint.
* Requests a DPoP-bound access token from the authorization server (`token_type=DPoP` per RFC 9449
  §5).
* Attaches a `DPoP` header — including the required `ath` (access token hash) claim — to every
  authenticated request sent to the resource server, and switches the `Authorization` scheme from
  `Bearer` to `DPoP`.
* Transparently handles the `use_dpop_nonce` challenge (RFC 9449 §8) from the authorization server
  by capturing the server-issued nonce and retrying the request once.

DPoP is disabled by default. To enable it, set `rest.auth.oauth2.dpop.enabled=true`.

## Quick Start

The minimal configuration is simply to turn DPoP on:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

rest.auth.oauth2.issuer-url=https://idp.example.com/realms/main
rest.auth.oauth2.grant-type=client_credentials
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-secret=s3cret
rest.auth.oauth2.scope=catalog

rest.auth.oauth2.dpop.enabled=true
```

With this configuration the AuthManager generates a fresh `ES256` keypair when it starts, uses it
for the lifetime of the agent, and discards it on shutdown. The authorization server must be
configured to accept DPoP-bound tokens for this client. For example, in Keycloak 26.x this means
enabling the `dpop` feature and setting `dpop.bound.access.tokens=true` on the client.

## Key Management

The AuthManager generates a fresh keypair each time the agent starts. The key lives entirely in
memory and never leaves the process. This is the simplest and most secure approach: a stolen access
token cannot be replayed without the private key, and the private key never leaves the agent's
memory.

A new key means a new `cnf.jkt` thumbprint on every fresh access token — any tokens issued to a
previous agent instance are no longer refreshable once that agent shuts down, since refresh requires
signing with the same key the original token was bound to (RFC 9449 §5). The AuthManager satisfies
this implicitly: it reuses a single key for the lifetime of the agent.

## Signing Algorithms

The signing algorithm is controlled by `rest.auth.oauth2.dpop.algorithm`. Per RFC 9449 the signing
key must be asymmetric; only RSA- and EC-family algorithms are accepted. The default is `ES256`,
which produces the smallest proofs.

| Algorithm | Key Type | Notes                                            |
|-----------|----------|--------------------------------------------------|
| `ES256`   | EC P-256 | Default. Smallest proofs.                        |
| `ES384`   | EC P-384 |                                                  |
| `ES512`   | EC P-521 |                                                  |
| `RS256`   | RSA      | Widely supported by authorization servers.       |
| `RS384`   | RSA      |                                                  |
| `RS512`   | RSA      |                                                  |
| `PS256`   | RSA      | RSASSA-PSS; preferred over `RS*` when available. |
| `PS384`   | RSA      |                                                  |
| `PS512`   | RSA      |                                                  |

`ES256K` (secp256k1) and the `EdDSA` family (Ed25519 / Ed448) are not currently supported.

The AuthManager generates a key matching the configured algorithm.

## Nonce Handling

RFC 9449 §8 lets the authorization server require the client to include a `nonce` claim in every
DPoP proof, supplying the current value via a `DPoP-Nonce` response header. The AuthManager handles
this transparently: the first request goes out without a `nonce` claim; if the server responds with
`400 use_dpop_nonce`, the AuthManager captures the `DPoP-Nonce` header value, re-signs the proof
with the `nonce` claim set, and retries the request once. Subsequent requests reuse the cached
nonce (and update it whenever the server refreshes it).

No configuration is needed — nonce challenges are handled automatically for the token endpoint.

## Known Limitations

* **Resource-server nonce challenges are not supported.** The underlying Iceberg `HTTPClient` does
  not surface response headers or 401 bodies back to the AuthManager, so a resource-server nonce
  challenge (RFC 9449 §9: a 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` accompanied by
  a `DPoP-Nonce` response header) cannot be observed and the nonce cannot be captured for the
  retry. If a resource server mandates per-request nonces, DPoP will fail against it until the
  Iceberg HTTPClient grows an interception hook. (Token-endpoint nonce challenges — which go through
  the AuthManager's own HTTP client — *are* supported.)

* **No key rotation.** The key lives as long as the agent. To rotate, restart the process.

## Full Configuration Reference

See the [Configuration](./configuration.md#dpop-settings) section for the full list of DPoP
configuration properties.

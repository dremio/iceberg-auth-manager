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
# Dremio AuthManager for Apache Iceberg - Client Authentication Methods

## Overview

The Dremio AuthManager for Apache Iceberg supports various OAuth2 client authentication methods to authenticate the client application to the authorization server when requesting an access token.

These methods are based on the client authentication methods defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), [RFC 6749, Section 2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1), and [RFC 7523, Section 2.2](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2).

## Choosing an Authentication Method

For enhanced security, we recommend using JWS-based authentication methods (`client_secret_jwt` or `private_key_jwt`) when possible, especially for production environments.

- Use `private_key_jwt` for the highest level of security;
- Use `client_secret_jwt` when you have a client secret but cannot use asymmetric keys;
- Use `client_secret_basic` or `client_secret_post` for simpler setups;
- Use `none` only for public clients that don't have a client secret (not recommended).

## Supported Authentication Methods

### Public Clients

#### `none`

The client does not authenticate itself at the token endpoint because it is a public client with no client secret or other authentication mechanism. This is the default method for public clients, that is, it will be automatically inferred if no client secret is provided.

Example configuration:

```properties
rest.auth.oauth2.client-auth=none
rest.auth.oauth2.client-id=my-public-client
```

In the above example, the `rest.auth.oauth2.client-auth` is optional and would default to `none` since no client secret is provided.

### Basic Authentication Methods

#### `client_secret_basic`

Clients that have received a client secret can authenticate using the HTTP Basic authentication scheme. This is the default method for private clients, that is, it will be automatically inferred if a client secret is provided.

Example configuration:

```properties
rest.auth.oauth2.client-auth=client_secret_basic
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-secret=my-secret
```

In the above example, the `rest.auth.oauth2.client-auth` is optional and would default to `client_secret_basic` since a client secret is provided.

#### `client_secret_post`

Clients that have received a client secret can also authenticate by including the client credentials in the request body. This method is less secure than `client_secret_basic` as the client secret is sent in clear text in the request body.

Example configuration:

```properties
rest.auth.oauth2.client-auth=client_secret_post
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-secret=my-secret
```

### JWT-Based Authentication Methods (Client Assertions)

#### `client_secret_jwt`

Clients that have received a client_secret value can create a JWT using an HMAC SHA algorithm, where the client secret is used as the key to sign the JWT.

This method provides enhanced security compared to basic authentication methods as it uses a signed JWT assertion instead of sending the client secret directly.

Example configuration:

```properties
rest.auth.oauth2.client-auth=client_secret_jwt
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-secret=my-secret
rest.auth.oauth2.client-assertion.jwt.algorithm=HMAC_SHA256
```

#### `private_key_jwt`

Clients that have registered a public key in the Authorization Server can sign a JWT using the corresponding private key. This is the most secure method as it uses asymmetric cryptography.

Example configuration:

```properties
rest.auth.oauth2.client-auth=private_key_jwt
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-assertion.jwt.algorithm=RSA_SHA256
rest.auth.oauth2.client-assertion.jwt.private-key=/path/to/private_key.pem
```

When using this method, the private key file must be provided using the `rest.auth.oauth2.client-assertion.jwt.private-key` property. The file must be in PEM format; it may contain a private key, or a private key and a certificate chain. Only the private key is used.

The authorization server then validates the signature using the client's registered public key.

#### Configuring JWT Assertions

The JWT assertion includes the following claims:

- `iss` (issuer): by default, the client ID
- `sub` (subject): by default, the client ID
- `aud` (audience): by default, the token endpoint URL (resolved or provided)
- `iat` (issued at): by default, the current time
- `exp` (expiration): by default, the current time plus 5 minutes

Each of these claims (except `iat`) can be customized using the following configuration properties:

```properties
rest.auth.oauth2.client-assertion.jwt.issuer=my-issuer
rest.auth.oauth2.client-assertion.jwt.subject=my-subject
rest.auth.oauth2.client-assertion.jwt.audience=https://example.com/token
rest.auth.oauth2.client-assertion.jwt.token-lifespan=PT10M
```

The signing algorithm can be specified using the `rest.auth.oauth2.client-assertion.jwt.algorithm` property. The default is `HMAC_SHA512` for `client_secret_jwt` and `RSA_SHA512` for `private_key_jwt` (algorithm names are case-insensitive). Example:

```properties
rest.auth.oauth2.client-assertion.jwt.algorithm=HMAC_SHA384
```

Supported algorithms are:

For `client_secret_jwt`:

| Algorithm     | Accepted Alternative Names |
|---------------|----------------------------|
| `HMAC_SHA256` | `HS256`, `HmacSHA256`      |
| `HMAC_SHA384` | `HS384`, `HmacSHA384`      |
| `HMAC_SHA512` | `HS512`, `HmacSHA512`      |

For `private_key_jwt`:

| Algorithm    | Accepted Alternative Names |
|--------------|----------------------------|
| `RSA_SHA256` | `RS256`, `SHA256withRSA`   |
| `RSA_SHA384` | `RS384`, `SHA384withRSA`   |
| `RSA_SHA512` | `RS512`, `SHA512withRSA`   |


And finally, extra claims can be added to the JWT assertion using the `rest.auth.oauth2.client-assertion.jwt.extra-claims.*` prefix property. Example:

```properties
rest.auth.oauth2.client-assertion.jwt.extra-claims.my-claim=my-value
```

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
# Dremio AuthManager for Apache Iceberg - Migration From Iceberg REST's Built-in OAuth2 AuthManager

## Overview

This document describes the differences between this `AuthManager`, and Iceberg's built-in OAuth2
`AuthManager`.

## Migrating Configuration Properties

Iceberg's built-in OAuth2 `AuthManager` properties are listed below, along with their equivalent
properties in this `AuthManager`.

| Legacy Property         | New Property                                                        |
|-------------------------|---------------------------------------------------------------------|
| `oauth2-server-uri`     | `rest.auth.oauth2.token-endpoint`                                   |
| `token`                 | `rest.auth.oauth2.token`                                            |
| `credential`            | `rest.auth.oauth2.client-id` <br/> `rest.auth.oauth2.client-secret` |
| `scope`                 | `rest.auth.oauth2.scope`                                            |
| `audience`              | `rest.auth.oauth2.token-exchange.audience`                          |
| `resource`              | `rest.auth.oauth2.token-exchange.resource`                          |
| `token-expires-in-ms`   | `rest.auth.oauth2.token-refresh.access-token-lifespan`              |
| `token-refresh-enabled` | `rest.auth.oauth2.token-refresh.enabled`                            |

Notes: 

- The token endpoint URL must be an absolute URL; relative URLs are not supported by this
  `AuthManager`.
- The `access-token-lifespan` property must be an ISO-8601 duration string, e.g. `PT55S` for 55
  seconds, `PT1H` for 1 hour, etc.

## Differences Between Auth Managers

### Supported Grant Types

Iceberg's built-in OAuth2 `AuthManager` can only handle the `client_credentials` grant type for an
initial token fetch.

Dremio Auth Manager provides support the following additional grant types:

- Resource Owner Password (`password`)
- Authorization Code (`authorization_code`)
- Device Code (`urn:ietf:params:oauth:grant-type:device_code`)
- Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)

### Supported Client Authentication Methods

Iceberg's built-in OAuth2 `AuthManager` uses a mix of `client_secret_basic` and `client_secret_post`
client authentication methods, depending on the situation.

Dremio Auth Manager provides support the following additional client authentication methods:

- None (Public Client) (`none`)
- Client Secret Basic (`client_secret_basic`)
- Client Secret Post (`client_secret_post`)
- Client Secret JWT (`client_secret_jwt`)
- Private Key JWT (`private_key_jwt`)

See [Client Authentication Methods](./client-authentication.md) for more details.

### Support for Static Bearer Access Tokens

Iceberg's built-in OAuth2 `AuthManager` supports static bearer access tokens via the `token`
property.

This is _not_ supported by Dremio Auth Manager as sharing bearer tokens is not a best practice, and
besides, static tokens cannot be refreshed using OAuth2 token refresh mechanisms (see below).

Note: Dremio Auth Manager _does_ support static subject and actor tokens when using the token
exchange grant type: this is a common use case for impersonation and delegation, and does not
preclude the use of OAuth2 token refresh mechanisms (see [Token Exchange](./token-exchange.md)).

### Token Refreshes

Iceberg's built-in OAuth2 `AuthManager` has a non-standard way of handling token refreshes, making
it difficult to use with external OAuth2 providers that respect the OAuth2 standard.

Dremio Auth Manager instead follows the OAuth2 standard for token refreshes:

* If a refresh token is provided in the initial token fetch, the token is refreshed using the
  `refresh_token` grant type. This is generally the case for all grant types other than
  `client_credentials`.

* Otherwise, a brand-new token is fetched using the configured initial grant type. This is generally
  the case for `client_credentials`.

This way, Dremio Auth Manager can work with any OAuth2 provider that follows the OAuth2 standard.

Note: with Iceberg 1.10 and later, Iceberg's built-in OAuth2 `AuthManager` also supports the OAuth2
standard way of handling token refreshes, when the `token-exchange-enabled` property is set to
`false`.

### Support for Delegation and Impersonation

Impersonation and delegation are two different ways of allowing a user to act on behalf of another
user. When using OAuth2, they generally leverage the token exchange grant type.

The Iceberg's built-in OAuth2 `AuthManager` does not support initial token exchange grants, and
therefore does not support impersonation and delegation.

Dremio Auth Manager supports token exchange for initial token fetches, and therefore supports
impersonation and delegation. See [Token Exchange](./token-exchange.md) for more details.

Note: Iceberg's built-in OAuth2 `AuthManager` does support the token exchange grant type, but it
does so for token refreshes only; however, this is not sufficient for impersonation and delegation,
which require an initial token exchange.


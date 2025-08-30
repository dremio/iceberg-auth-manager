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
# Dremio AuthManager for Apache Iceberg - Configuration

## Overview

Dremio AuthManager for Apache Iceberg is highly configurable. The configuration is done via
properties passed to the `OAuthManager` class at runtime. The properties are specified when
initializing the catalog.

To enable the Dremio AuthManager for Apache Iceberg, you need to set the `rest.auth.type` property
to `com.dremio.iceberg.authmgr.oauth2.OAuth2Manager` in your catalog configuration:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager
```

Other properties are listed below.

> [!WARNING]
> This page is automatically generated from the code. Do not edit it manually.
> To update this page, run: `./gradlew :authmgr-docs-generator:generateDocs`.

## Basic Settings

Basic OAuth2 properties. These properties are used to configure the basic OAuth2 options such as the issuer URL, token endpoint, client ID, and client secret.

### `rest.auth.oauth2.token`

The initial access token to use. Optional. If this is set, the agent will not attempt to fetch the first new token from the Authorization server, but will use this token instead.

This option is mostly useful when migrating from the Iceberg OAuth2 manager to this OAuth2 manager. Always prefer letting the agent fetch an initial token from the configured Authorization server.

When this option is set, the token is not validated by the agent, and it's not always possible to refresh it. It's recommended to use this option only for testing purposes, or if you know that the token is valid and will not expire too soon.

### `rest.auth.oauth2.issuer-url`

OAuth2 issuer URL.

The root URL of the Authorization server, which will be used for discovering supported endpoints and their locations. For Keycloak, this is typically the realm URL: `https://<keycloak-server>/realms/<realm-name>`.

Two "well-known" paths are supported for endpoint discovery: `.well-known/openid-configuration` and `.well-known/oauth-authorization-server`. The full metadata discovery URL will be constructed by appending these paths to the issuer URL.

Either this property or `rest.auth.oauth2.token-endpoint` must be set.

### `rest.auth.oauth2.token-endpoint`

URL of the OAuth2 token endpoint. For Keycloak, this is typically `https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/token`.

Either this property or `rest.auth.oauth2.issuer-url` must be set. In case it is not set, the token endpoint will be discovered from the issuer URL (`rest.auth.oauth2.issuer-url`), using the OpenID Connect Discovery metadata published by the issuer.

### `rest.auth.oauth2.grant-type`

The grant type to use when authenticating against the OAuth2 server. Valid values are:

- client_credentials (`client_credentials`)
- password (`password`)
- authorization_code (`authorization_code`)
- urn:ietf:params:oauth:grant-type:device_code (`urn:ietf:params:oauth:grant-type:device_code`)
- urn:ietf:params:oauth:grant-type:token-exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)

Optional, defaults to `client_credentials`.

### `rest.auth.oauth2.client-id`

Client ID to use when authenticating against the OAuth2 server. Required, unless a static token (`rest.auth.oauth2.token`) is provided.

### `rest.auth.oauth2.client-auth`

The OAuth2 client authentication method to use. Valid values are:

- none (`none`): the client does not authenticate itself at the token endpoint, because it is a public client with no client secret or other authentication mechanism.
- client_secret_basic (`client_secret_basic`): client secret is sent in the HTTP Basic Authorization header.
- client_secret_post (`client_secret_post`): client secret is sent in the request body as a form parameter.
- client_secret_jwt (`client_secret_jwt`): client secret is used to sign a JWT token.
- private_key_jwt (`private_key_jwt`): client authenticates with a JWT assertion signed with a private key.

The default is `client_secret_basic`.

### `rest.auth.oauth2.client-secret`

Client secret to use when authenticating against the OAuth2 server. Required if the client is private and is authenticated using the standard "client-secret" methods. If other authentication methods are used (e.g. `private_key_jwt`), this property is ignored.

### `rest.auth.oauth2.scope`

Space-separated list of scopes to include in each request to the OAuth2 server. Optional, defaults to empty (no scopes).

The scope names will not be validated by the OAuth2 agent; make sure they are valid according to [RFC 6749 Section 3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).

### `rest.auth.oauth2.extra-params.`

Extra parameters to include in each request to the token endpoint. This is useful for custom parameters that are not covered by the standard OAuth2.0 specification. Optional, defaults to empty.

This is a prefix property, and multiple values can be set, each with a different key and value. The values must NOT be URL-encoded. Example:

```
rest.auth.oauth2.extra-params.custom_param1=custom_value1"
rest.auth.oauth2.extra-params.custom_param2=custom_value2"
```

For example, Auth0 requires the `audience` parameter to be set to the API identifier. This can be done by setting the following configuration:

```
rest.auth.oauth2.extra-params.audience=https://iceberg-rest-catalog/api
```

### `rest.auth.oauth2.timeout`

Defines how long the agent should wait for tokens to be acquired. Optional, defaults to `PT5M`.

## Client Assertion Settings

Configuration properties for JWT client assertion as specified in [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523).

These properties allow the client to authenticate using the `client_secret_jwt` or `private_key_jwt` authentication methods.

### `rest.auth.oauth2.client-assertion.jwt.issuer`

The issuer of the client assertion JWT. Optional. The default is the client ID.

### `rest.auth.oauth2.client-assertion.jwt.subject`

The subject of the client assertion JWT. Optional. The default is the client ID.

### `rest.auth.oauth2.client-assertion.jwt.audience`

The audience of the client assertion JWT. Optional. The default is the token endpoint.

### `rest.auth.oauth2.client-assertion.jwt.token-lifespan`

The expiration time of the client assertion JWT. Optional. The default is 5 minutes.

### `rest.auth.oauth2.client-assertion.jwt.algorithm`

The signing algorithm to use for the client assertion JWT. Optional. The default is `HS512` if the authentication method is `client_secret_jwt`, or `RS512` if the authentication method is `private_key_jwt`.

Algorithm names must match the "alg" Param Value as described in [RFC 7518 Section 3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).

### `rest.auth.oauth2.client-assertion.jwt.private-key`

The path on the local filesystem to the private key to use for signing the client assertion JWT. Required if the authentication method is `private_key_jwt`. The file must be in PEM format; it may contain a private key, or a private key and a certificate chain. Only the private key is used.

### `rest.auth.oauth2.client-assertion.jwt.extra-claims.`

Extra claims to include in the client assertion JWT. This is a prefix property, and multiple values can be set, each with a different key and value.

## Token Refresh Settings

Configuration properties for the token refresh feature.

### `rest.auth.oauth2.token-refresh.enabled`

Whether to enable token refresh. If enabled, the agent will automatically refresh its access token when it expires. If disabled, the agent will only fetch the initial access token, but won't refresh it. Defaults to `true`.

### `rest.auth.oauth2.token-refresh.access-token-lifespan`

Default access token lifespan; if the OAuth2 server returns an access token without specifying its expiration time, this value will be used. Note that when this happens, a warning will be logged.

Optional, defaults to `PT5M`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

### `rest.auth.oauth2.token-refresh.safety-window`

Refresh safety window to use; a new token will be fetched when the current token's remaining lifespan is less than this value. Optional, defaults to `PT10S`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

### `rest.auth.oauth2.token-refresh.idle-timeout`

Defines for how long the OAuth2 manager should keep the tokens fresh, if the agent is not being actively used. Setting this value too high may cause an excessive usage of network I/O and thread resources; conversely, when setting it too low, if the agent is used again, the calling thread may block if the tokens are expired and need to be renewed synchronously. Optional, defaults to `PT30S`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

## Resource Owner Settings

Configuration properties for the [Resource Owner Password Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) flow.

Note: according to the [OAuth 2.0 Security Best Current Practice, section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4) this flow should NOT be used anymore because it "insecurely exposes the credentials of the resource owner to the client".

### `rest.auth.oauth2.resource-owner.username`

Username to use when authenticating against the OAuth2 server. Required if using OAuth2 authentication and `password` grant type, ignored otherwise.

### `rest.auth.oauth2.resource-owner.password`

Password to use when authenticating against the OAuth2 server. Required if using OAuth2 authentication and the `password` grant type, ignored otherwise.

## Authorization Code Settings

Configuration properties for the [Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) flow.

This flow is used to obtain an access token by redirecting the user to the OAuth2 authorization server, where they can log in and authorize the client application to access their resources.

### `rest.auth.oauth2.auth-code.endpoint`

URL of the OAuth2 authorization endpoint. For Keycloak, this is typically `https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth`.

If using the "authorization_code" grant type, either this property or `rest.auth.oauth2.issuer-url` must be set. In case it is not set, the authorization endpoint will be discovered from the issuer URL (`rest.auth.oauth2.issuer-url`), using the OpenID Connect Discovery metadata published by the issuer.

### `rest.auth.oauth2.auth-code.redirect-uri`

The redirect URI. This is the value of the `redirect_uri` parameter in the authorization code request.

Optional; if not present, the URL will be computed from `rest.auth.oauth2.auth-code.callback-bind-host`, `rest.auth.oauth2.auth-code.callback-bind-port` and `rest.auth.oauth2.auth-code.callback-context-path`.

Specifying this value is generally only necessary in containerized environments, if a reverse proxy modifies the callback before it reaches the client, or if external TLS termination is performed.

### `rest.auth.oauth2.auth-code.callback-bind-host`

Address of the OAuth2 authorization code flow local web server.

The internal web server will listen for the authorization code callback on this address. This is only used if the grant type to use is `authorization_code`.

Optional; if not present, the server will listen on the loopback interface.

### `rest.auth.oauth2.auth-code.callback-bind-port`

Port of the OAuth2 authorization code flow local web server.

The internal web server will listen for the authorization code callback on this port. This is only used if the grant type to use is `authorization_code`.

Optional; if not present, a random port will be used.

### `rest.auth.oauth2.auth-code.callback-context-path`

Context path of the OAuth2 authorization code flow local web server.

Optional; if not present, a default context path will be used.

### `rest.auth.oauth2.auth-code.pkce.enabled`

Whether to enable PKCE (Proof Key for Code Exchange) for the authorization code flow. The default is `true`.

### `rest.auth.oauth2.auth-code.pkce.method`

The PKCE code challenge method to use. The default is `S256`. This is only used if PKCE is enabled.

## Device Code Settings

Configuration properties for the [Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) flow.

This flow is used to obtain an access token for devices that do not have a browser or limited input capabilities. The user is prompted to visit a URL on another device and enter a code to authorize the device.

### `rest.auth.oauth2.device-code.endpoint`

URL of the OAuth2 device authorization endpoint. For Keycloak, this is typically `http://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth/device`.

If using the "Device Code" grant type, either this property or `rest.auth.oauth2.issuer-url` must be set.

### `rest.auth.oauth2.device-code.poll-interval`

Defines how often the agent should poll the OAuth2 server for the device code flow to complete. This is only used if the grant type to use is `urn:ietf:params:oauth:grant-type:device_code`. Optional, defaults to `PT5S`.

## Token Exchange Settings

Configuration properties for the [Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) flow.

This flow allows a client to exchange one token for another, typically to obtain a token that is more suitable for the target resource or service.

### `rest.auth.oauth2.token-exchange.subject-token`

For token exchanges only. The subject token to exchange.

If this value is present, the subject token will be used as-is. If this value is not present, the subject token will be dynamically fetched using the configuration provided under the `rest.auth.oauth2.token-exchange.subject-token.` prefix.

### `rest.auth.oauth2.token-exchange.subject-token-type`

For token exchanges only. The type of the subject token. Must be a valid URN. The default is `urn:ietf:params:oauth:token-type:access_token`.

### `rest.auth.oauth2.token-exchange.actor-token`

For token exchanges only. The actor token to exchange.

If this value is present, the actor token will be used as-is. If this value is not present, the actor token will be dynamically fetched using the configuration provided under the `rest.auth.oauth2.token-exchange.actor-token.` prefix. If no configuration is provided, no actor token will be used.

### `rest.auth.oauth2.token-exchange.actor-token-type`

For token exchanges only. The type of the actor token. Must be a valid URN. The default is `urn:ietf:params:oauth:token-type:access_token`.

If the agent is configured to dynamically fetch the actor token, this property is ignored since only access tokens can be dynamically fetched.

### `rest.auth.oauth2.token-exchange.requested-token-type`

For token exchanges only. The type of the requested security token. Must be a valid URN. The default is `urn:ietf:params:oauth:token-type:access_token`.

### `rest.auth.oauth2.token-exchange.subject-token.`

For token exchanges only. The configuration to use for fetching the subject token. Required if `rest.auth.oauth2.token-exchange.subject-token` is not set.

This is a prefix property; any property that can be set under the `rest.auth.oauth2.` prefix can also be set under this prefix.

The effective subject token fetch configuration will be the result of merging the subject-specific configuration with the main configuration.

Example:

```
rest.auth.oauth2.grant-type=token_exchange
rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
rest.auth.oauth2.client-id=main-client-id
rest.auth.oauth2.client-secret=main-client-secret
rest.auth.oauth2.token-exchange.subject-token.grant-type=client_credentials
rest.auth.oauth2.token-exchange.subject-token.client-id=subject-client-id
rest.auth.oauth2.token-exchange.subject-token.client-secret=subject-client-secret
```

The above configuration will result in a token exchange where the subject token is obtained using the client credentials grant type, with specific client ID and secret, but sharing the token endpoint, client authentication method and other settings with the main agent.

### `rest.auth.oauth2.token-exchange.actor-token.`

For token exchanges only. The configuration to use for fetching the actor token. Optional; required only if `rest.auth.oauth2.token-exchange.actor-token` is not set but an actor token is required.

This is a prefix property; any property that can be set under the `rest.auth.oauth2.` prefix can also be set under this prefix.

The effective actor token fetch configuration will be the result of merging the actor-specific configuration with the main configuration.

Example:

```
rest.auth.oauth2.grant-type=token_exchange
rest.auth.oauth2.token-endpoint=https://main-token-endpoint.com/token
rest.auth.oauth2.client-id=main-client-id
rest.auth.oauth2.client-secret=main-client-secret
rest.auth.oauth2.token-exchange.actor-token.grant-type=client_credentials
rest.auth.oauth2.token-exchange.actor-token.client-id=actor-client-id
rest.auth.oauth2.token-exchange.actor-token.client-secret=actor-client-secret
```

The above configuration will result in a token exchange where the actor token is obtained using the client credentials grant type, with specific client ID and secret, but sharing the token endpoint, client authentication method and other settings with the main agent.

### `rest.auth.oauth2.token-exchange.resource`

For token exchanges only. A space-separatee list of URIs that indicate the target service(s) or resource(s) where the client intends to use the requested security token. Optional.

### `rest.auth.oauth2.token-exchange.audience`

For token exchanges only. A space-separated list of logical names of the target service(s) where the client intends to use the requested security token. This serves a purpose similar to the resource parameter but with the client providing a logical name for the target service.

## System Settings

Configuration properties for the whole system.

These properties are used to configure properties such as the session cache timeout and the HTTP client type.

### `rest.auth.oauth2.system.agent-name`

The distinctive name of the OAuth2 agent. Defaults to `iceberg-auth-manager`. This name is printed in all log messages and user prompts.

### `rest.auth.oauth2.system.session-cache-timeout`

The session cache timeout. Cached sessions will become eligible for eviction after this duration of inactivity. Defaults to `PT1H`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

This value is used for housekeeping; it does not mean that cached sessions will stop working after this time, but that the session cache will evict the session after this time of inactivity. If the context is used again, a new session will be created and cached.

## Http Settings

Configuration properties for HTTP communication.

### `rest.auth.oauth2.http.client-type`

The type of HTTP client to use for making HTTP requests to the OAuth2 server. Valid values are:

- `default`: uses the built-in URLConnection-based client provided by the underlying OAuth2 library.
- `apache`: uses the Apache HttpClient library, provided by Iceberg's runtime.

Optional, defaults to `default`.

### `rest.auth.oauth2.http.read-timeout`

The read timeout for HTTP requests. Optional, defaults to `PT30S`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.connect-timeout`

The connection timeout for HTTP requests. Optional, defaults to `PT10S`. Must be a valid [ISO-8601 duration](https://en.wikipedia.org/wiki/ISO_8601#Durations).

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.headers.`

HTTP headers to include in each HTTP request. This is a prefix property, and multiple values can be set, each with a different key and value.

### `rest.auth.oauth2.http.compression.enabled`

Whether to enable compression for HTTP requests. Optional, defaults to `true`.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.protocols`

A comma-separated list of SSL protocols to use for HTTPS requests. Optional, defaults to the system protocols.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.cipher-suites`

A comma-separated list of SSL cipher suites to use for HTTPS requests. Optional, defaults to the system cipher suites.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.hostname-verification.enabled`

Whether to enable SSL hostname verification for HTTPS requests.

WARNING: Disabling hostname verification is a security risk and should only be used for testing purposes.

Optional, defaults to `true`.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.trust-all`

Whether to trust all SSL certificates for HTTPS requests.

WARNING: Trusting all SSL certificates is a security risk and should only be used for testing purposes.

Optional, defaults to `false`.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.trust-store.path`

Path to the trust store to use for HTTPS requests. Optional, defaults to the system trust store.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.ssl.trust-store.password`

Password for the trust store to use for HTTPS requests. Optional, defaults to no password.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`, or if `rest.auth.oauth2.http.ssl.trust-store.path` is not set.

### `rest.auth.oauth2.http.proxy.host`

Proxy host to use for HTTP requests. Optional, defaults to no proxy. If set, the proxy port must also be set.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.proxy.port`

Proxy port to use for HTTP requests. Optional, defaults to no proxy. If set, the proxy host must also be set.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.proxy.username`

Proxy username to use for HTTP requests. Optional, defaults to no authentication. If set, the proxy password must also be set.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.

### `rest.auth.oauth2.http.proxy.password`

Proxy password to use for HTTP requests. Optional, defaults to no authentication. If set, the proxy username must also be set.

This setting is ignored when the client type (`rest.auth.oauth2.http.client-type`) is set to `default`.


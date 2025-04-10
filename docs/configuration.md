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

## Basic Settings

### `rest.auth.oauth2.token`

The initial access token to use. Optional. If this is set, the agent will not attempt to
fetch the first new token from the Authorization server, but will use this token instead.

This option is mostly useful when migrating from the Iceberg OAuth2 manager to this OAuth2
manager. Always prefer letting the agent fetch an initial token from the configured
Authorization server.

When this option is set, the token is not validated by the agent, and it's not always
possible to refresh it. It's recommended to use this option only for testing purposes, or if
you know that the token is valid and will not expire too soon.

### `rest.auth.oauth2.issuer-url`

OAuth2 issuer URL.

The root URL of the Authorization server, which will be used for discovering supported endpoints and
their locations. For Keycloak, this is typically the realm URL:
<code>https://&lt;keycloak-server>/realms/&lt;realm-name></code>.

Two "well-known" paths are supported for endpoint discovery:
<code>.well-known/openid-configuration</code> and
<code>.well-known/oauth-authorization-server</code>. The full metadata discovery URL will be
constructed by appending these paths to the issuer URL.

Either this property or `rest.auth.oauth2.token-endpoint` must be set.

### `rest.auth.oauth2.token-endpoint`

URL of the OAuth2 token endpoint. For Keycloak, this is typically
<code>https://&lt;keycloak-server>/realms/&lt;realm-name>/protocol/openid-connect/token</code>.

Either this property or `rest.auth.oauth2.issuer-url` must be set. In case it is not set, the token
endpoint will be discovered from the issuer URL, using the OpenID Connect
Discovery metadata published by the issuer.

### `rest.auth.oauth2.grant-type`

The grant type to use when authenticating against the OAuth2 server. Valid values are:

<ul>
  <li><code>client_credentials</code>
  <li><code>password</code>
  <li><code>authorization_code</code>
  <li><code>device_code</code>
  <li><code>token_exchange</code>
</ul>

Optional, defaults to `client_credentials`.

### `rest.auth.oauth2.client-id`

Client ID to use when authenticating against the OAuth2 server. Required, unless using the
Iceberg OAuth2 dialect.

### `rest.auth.oauth2.client-auth`

The OAuth2 client authentication method to use. Valid values are:

<ul>
  <li><code>none</code>: the client does not authenticate itself at the token endpoint, because it
      is a public client with no client secret or other authentication mechanism.
  <li><code>client_secret_basic</code>: client secret is sent in the HTTP Basic Authorization
      header.
  <li><code>client_secret_post</code>: client secret is sent in the request body as a form
      parameter.
</ul>

The default is <code>client_secret_basic</code> if the client is private, or <code>none</code> if the
client is public.

This property is ignored when then dialect is Iceberg OAuth2 dialect
or when a token is provided.

### `rest.auth.oauth2.client-secret`

Client secret to use when authenticating against the OAuth2 server. Required if the client is
private.

### `rest.auth.oauth2.scope`

Space-separated list of scopes to include in each request to the OAuth2 server. Optional,
defaults to empty (no scopes).

The scope names will not be validated by the OAuth2 agent; make sure they are valid
according to <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749
Section 3.3</a>.

### `rest.auth.oauth2.extra-params.*`

Extra parameters to include in each request to the token endpoint. This is useful for custom
parameters that are not covered by the standard OAuth2.0 specification. Optional, defaults to
empty.

This is a prefix property, and multiple values can be set, each with a different key and
value. The values must NOT be URL-encoded. Example:

<pre>
rest.auth.oauth2.extra-params.custom_param1=custom_value1"
rest.auth.oauth2.extra-params.custom_param2=custom_value2"
</pre>

For example, Auth0 requires the <code>audience</code> parameter to be set to the API identifier.
This can be done by setting the following configuration:

<pre>
rest.auth.oauth2.extra-params.audience=https://iceberg-rest-catalog/api
</pre>

### `rest.auth.oauth2.dialect`

The OAuth2 dialect. Possible values are: `standard` and `iceberg_rest`.

If the Iceberg dialect is selected, the agent will behave exactly like the built-in OAuth2
manager from Iceberg Core. This dialect should only be selected if the token endpoint is
internal to the REST catalog server, and the server is configured to understand this dialect.

The Iceberg dialect's main differences from standard OAuth2 are:

<ul>
  <li>Only <code>client_credentials</code> grant type is supported;
  <li>Token refreshes are done with the <code>token_exchange</code> grant type;
  <li>Token refreshes are done with Bearer authentication, not Basic authentication;
  <li>Public clients are not supported, however client secrets without client IDs are
      supported;
  <li>Client ID and client secret are sent as request body parameters, and not as Basic
      authentication.
</ul>

Optional. The default value is `iceberg_rest` if either `rest.auth.oauth2.token` is provided
or `rest.auth.oauth2.token-endpoint` contains a relative URI, and `standard` otherwise.

## Token Refresh Settings

### `rest.auth.oauth2.token-refresh.enabled`

Whether to enable token refresh. If enabled, the agent will automatically refresh its access
token when it expires. If disabled, the agent will only fetch the initial access token, but
won't refresh it. Defaults to <code>true</code>.

### `rest.auth.oauth2.token-refresh.access-token-lifespan`

Default access token lifespan; if the OAuth2 server returns an access token without
specifying its expiration time, this value will be used. Note that when this happens, a
warning will be logged.

Optional, defaults to `PT5M`. Must be a valid <a
href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.

### `rest.auth.oauth2.token-refresh.safety-window`

Refresh safety window to use; a new token will be fetched when the current token's remaining
lifespan is less than this value. Optional, defaults to `PT10S`. Must
be a valid <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.

### `rest.auth.oauth2.token-refresh.idle-timeout`

Defines for how long the OAuth2 manager should keep the tokens fresh, if the agent is not
being actively used. Setting this value too high may cause an excessive usage of network I/O
and thread resources; conversely, when setting it too low, if the agent is used again, the
calling thread may block if the tokens are expired and need to be renewed synchronously.
Optional, defaults to `PT30S`. Must be a valid <a
href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.

## Resource Owner Flow Settings

### `rest.auth.oauth2.resource-owner.username`

Username to use when authenticating against the OAuth2 server. Required if using OAuth2
authentication and "password" grant type, ignored otherwise.

### `rest.auth.oauth2.resource-owner.password`

Password to use when authenticating against the OAuth2 server. Required if using OAuth2
authentication and the "password" grant type, ignored otherwise.

## Authorization Code Flow Settings

### `rest.auth.oauth2.auth-code.endpoint`

URL of the OAuth2 authorization endpoint. For Keycloak, this is typically
<code>https://&lt;keycloak-server>/realms/&lt;realm-name>/protocol/openid-connect/auth</code>.

If using the "authorization_code" grant type, either this property or `rest.auth.oauth2.issuer-url`
must be set. In case it is not set, the authorization endpoint will be discovered from the issuer
URL, using the OpenID Connect Discovery metadata published by the issuer.

### `rest.auth.oauth2.auth-code.redirect-uri`

The redirect URI. This is the value of the <code>redirect_uri</code> parameter in the
authorization code request.

Optional; if not present, the URL will be computed from
`rest.auth.oauth2.auth-code.callback-bind-host`, `rest.auth.oauth2.auth-code.callback-bind-port` and
`rest.auth.oauth2.auth-code.callback-context-path`.

Specifying this value is generally only necessary in containerized environments, if a
reverse proxy modifies the callback before it reaches the client, or if external TLS
termination is performed.

### `rest.auth.oauth2.auth-code.callback-bind-host`

Address of the OAuth2 authorization code flow local web server.

The internal web server will listen for the authorization code callback on this address.
This is only used if the grant type to use is `authorization_code`.

Optional; if not present, the server will listen on the loopback interface.

### `rest.auth.oauth2.auth-code.callback-bind-port`

Port of the OAuth2 authorization code flow local web server.

The internal web server will listen for the authorization code callback on this port. This
is only used if the grant type to use is `authorization_code`.

Optional; if not present, a random port will be used.

### `rest.auth.oauth2.auth-code.callback-context-path`

Context path of the OAuth2 authorization code flow local web server.

Optional; if not present, a default context path will be used.

### `rest.auth.oauth2.auth-code.timeout`

Defines how long the agent should wait for the authorization code flow to complete. In other words,
how long the agent should wait for the user to log in and authorize the application. This is only
used if the grant type to use is `authorization_code`. Optional, defaults to `PT5M`.

### `rest.auth.oauth2.auth-code.pkce.enabled`

Whether to enable PKCE (Proof Key for Code Exchange) for the authorization code flow. The
default is <code>true</code>.

### `rest.auth.oauth2.auth-code.pkce.transformation`

The PKCE transformation to use. The default is <code>S256</code>. This is only used if PKCE is
enabled.

## Device Code Flow Settings

### `rest.auth.oauth2.device-code.endpoint`

URL of the OAuth2 device authorization endpoint. For Keycloak, this is typically
<code>http://&lt;keycloak-server>/realms/&lt;realm-name>/protocol/openid-connect/auth/device</code>.

If using the "Device Code" grant type, either this property or `rest.auth.oauth2.issuer-url`
must be set.

### `rest.auth.oauth2.device-code.timeout`

Defines how long the agent should wait for the device code flow to complete.  In other words,
how long the agent should wait for the user to log in and authorize the application. This is only
used if the grant type to use is `device_code`. Optional, defaults to
`PT5M`.

### `rest.auth.oauth2.device-code.poll-interval`

Defines how often the agent should poll the OAuth2 server for the device code flow to
complete. This is only used if the grant type to use is `device_code`. Optional, defaults to `PT5S`.

## Token Exchange Flow Settings

### `rest.auth.oauth2.token-exchange.resource`

For token exchanges only. A URI that indicates the target service or resource where the
client intends to use the requested security token. Optional.

### `rest.auth.oauth2.token-exchange.audience`

For token exchanges only. The logical name of the target service where the client intends to
use the requested security token. This serves a purpose similar to the resource parameter but
with the client providing a logical name for the target service.

### `rest.auth.oauth2.token-exchange.subject-token`

For token exchanges only. The subject token to exchange. This can take 2 kinds of values:

<ul>
  <li>The value <code>current_access_token</code>, if the agent should use its current access
      token;
  <li>An arbitrary token: in this case, the agent will always use the static token provided
      here.
</ul>

The default is to use the current access token. Note: when using token exchange as the
initial grant type, no current access token will be available: in this case, a valid, static
subject token to exchange must be provided via configuration.

### `rest.auth.oauth2.token-exchange.subject-token-type`

For token exchanges only. The type of the subject token. Must be a valid URN. The default is
<code>urn:ietf:params:oauth:token-type:access_token</code>.

If the agent is configured to use its access token as the subject token, please note that
if an incorrect token type is provided here, the token exchange could fail.

### `rest.auth.oauth2.token-exchange.actor-token`

For token exchanges only. The actor token to exchange. This can take 2 kinds of values:

<ul>
  <li>The value <code>current_access_token</code>, if the agent should use its current access
      token;
  <li>An arbitrary token: in this case, the agent will always use the static token provided
      here.
</ul>

The default is to not include any actor token.

### `rest.auth.oauth2.token-exchange.actor-token-type`

For token exchanges only. The type of the actor token. Must be a valid URN. The default is
<code>urn:ietf:params:oauth:token-type:access_token</code>.

If the agent is configured to use its access token as the actor token, please note that if
an incorrect token type is provided here, the token exchange could fail.

## Runtime Settings

### `rest.auth.oauth2.runtime.agent-name`

The distinctive name of the OAuth2 agent. Defaults to `iceberg-auth-manager`. This name
is printed in all log messages and user prompts.

### `rest.auth.oauth2.runtime.session-cache-timeout`

The session cache timeout. Cached sessions will become eligible for eviction after this
duration of inactivity. Defaults to `PT1H`. Must be a valid
<a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.

This value is used for housekeeping; it does not mean that cached sessions will stop
working after this time, but that the session cache will evict the session after this time of
inactivity. If the context is used again, a new session will be created and cached.


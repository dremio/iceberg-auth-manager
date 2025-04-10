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
# Dremio AuthManager for Apache Iceberg - Impersonation & Delegation

## Overview

The Dremio AuthManager for Apache Iceberg supports impersonation and delegation using the
token exchange grant type. This allows a user to act on behalf of another user by
configuring a token exchange grant appropriately. 

When impersonation is enabled, a token exchange happens immediately after the initial token fetch,
allowing the client to act on behalf of another user. The impersonated user is generally specified
in the `subject_token` property of the token exchange request.

Impersonation flows support two distinct IDPs: a primary IDP and an impersonation IDP. The primary
IDP is used to obtain an initial access token, and the impersonation IDP is used to exchange the
initial access token. It is also possible to use the same IDP for both primary and impersonation
flows.

Impersonation or delegation is enabled and configured using the `rest.auth.oauth2.impersonation.*`
properties. Details about how impersonation happens can be further configured using the
`rest.auth.oauth2.token-exchange.*` properties.

## Impersonation Example

Here is a simple example of how to configure impersonation:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

# Primary IDP settings
rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=device_code
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

# Impersonation settings
rest.auth.oauth2.impersonation.enabled=true
rest.auth.oauth2.impersonation.issuer-url=https://$SECONDARY_IDP/realms/secondary
rest.auth.oauth2.impersonation.client-id=Client2
rest.auth.oauth2.impersonation.client-secret=$CLIENT2_SECRET
rest.auth.oauth2.impersonation.scope=catalog2

# Token exchange settings to customize the impersonation
rest.auth.oauth2.token-exchange.subject-token-type=urn:ietf:params:oauth:token-type:jwt
```

In this example, the primary IDP is used to obtain an initial access token using the
`device_code` grant type. The impersonation IDP is then used to exchange the initial access token
for a new access token using the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.

## Delegation Example

Here is a more complex example involving both impersonation and delegation:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

# Primary IDP settings
rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=authorization_code
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

# Impersonation settings
rest.auth.oauth2.impersonation.enabled=true
rest.auth.oauth2.impersonation.issuer-url=https://$SECONDARY_IDP/realms/secondary
rest.auth.oauth2.impersonation.scope=catalog2
rest.auth.oauth2.impersonation.client-id=Client2
rest.auth.oauth2.impersonation.client-secret=$CLIENT2_SECRET

# Token exchange settings to customize the impersonation
rest.auth.oauth2.token-exchange.actor-token-type=urn:ietf:params:oauth:token-type:jwt
rest.auth.oauth2.token-exchange.actor-token=$ACTOR_TOKEN
```

In this example, the primary IDP is used to obtain an initial access token using the
`authorization_code` grant type. The impersonation IDP is then used to exchange the initial access
token for a new access token using the `urn:ietf:params:oauth:grant-type:token-exchange` grant type.
The `actor-token` property is used to specify the actor token to be used in the token exchange
request. In this case, the actor token is a JWT token, obtained off-band.

## Impersonation & Delegation Settings

### `rest.auth.oauth2.impersonation.enabled`

Whether to enable "impersonation" mode. If enabled, each access token obtained from the
OAuth2 server using the configured initial grant type will be exchanged for a new token,
using the token exchange grant type.

### `rest.auth.oauth2.impersonation.issuer-url`

For impersonation only. The root URL of the OpenID Connect identity issuer provider.

Either this property or `rest.auth.oauth2.impersonation.token-endpoint` must be provided.

Endpoint discovery is performed using the OpenID Connect Discovery metadata published by
the issuer. See <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID
Connect Discovery 1.0</a> for more information.

### `rest.auth.oauth2.impersonation.token-endpoint`

For impersonation only. The URL of the OAuth2 token endpoint to use.

Either this property or `rest.auth.oauth2.impersonation.issuer-url` must be provided.

### `rest.auth.oauth2.impersonation.client-id`

For impersonation only. The client ID to use.

### `rest.auth.oauth2.impersonation.client-auth`

For impersonation only. The client authentication method to use. Valid values are:

<ul>
  <li><code>none</code>: the client does not authenticate itself at the token endpoint, because it
      is a public client with no client secret or other authentication mechanism.
  <li><code>client_secret_basic</code>: client secret is sent in the HTTP Basic Authorization
      header.
  <li><code>client_secret_post</code>: client secret is sent in the request body as a form
      parameter.
</ul>

The default is <code>client_secret_basic</code> if the client is private, or <code>none</code> if
the client is public.

### `rest.auth.oauth2.impersonation.client-secret`

For impersonation only. The client secret to use, if `rest.auth.oauth2.impersonation.client-id` is
defined and the token exchange client is confidential.

### `rest.auth.oauth2.impersonation.scope`

For impersonation only. Space-separated list of scopes to include in each token exchange
request to the OAuth2 server. Optional.

The scope names will not be validated by the OAuth2 agent; make sure they are valid
according to <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749
Section 3.3</a>.

### `rest.auth.oauth2.impersonation.extra-params.*`

Extra parameters to include in each request to the token endpoint, when using impersonation.

This is a prefix property, and multiple values can be set, each with a different key and value. The
values must NOT be URL-encoded. Example:

<pre>
rest.auth.oauth2.impersonation.extra-params.custom_param1=custom_value1"
rest.auth.oauth2.impersonation.extra-params.custom_param2=custom_value2"
</pre>

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


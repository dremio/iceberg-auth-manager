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
# Dremio AuthManager for Apache Iceberg - Token Exchange

## Overview

The Dremio AuthManager for Apache Iceberg supports the [Token Exchange] grant type. This grant
allows a subject to act on behalf of another subject by exchanging their tokens. Token exchanges are
typically used for impersonation and delegation.

[Token Exchange]: https://datatracker.ietf.org/doc/html/rfc8693

Token exchange flows are not prescriptive about how the subject and actor tokens are obtained, or
what they represent. The Dremio AuthManager for Apache Iceberg strives to preserve this flexibility.
Specifically, it enables subject and actor tokens to be provided in two methods:

* Static tokens: tokens acquired externally and directly included in the configuration. 
* Dynamic fetching: tokens are fetched dynamically by the AuthManager, using the same or different
  credentials and possibly a different IDP.

### Using Static Tokens

Static subject and actor tokens are provided in the configuration using the following properties,
respectively:

* `rest.auth.oauth2.token-exchange.subject-token`
* `rest.auth.oauth2.token-exchange.actor-token`

Additionally, the type of the subject and actor tokens can be specified using the following
properties, respectively:

* `rest.auth.oauth2.token-exchange.subject-token-type`
* `rest.auth.oauth2.token-exchange.actor-token-type`

Here is a simple example of how to configure the AuthManager with static tokens:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

# Basic settings
rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=token_exchange
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

# Subject token settings
rest.auth.oauth2.token-exchange.subject-token=$SUBJECT_TOKEN
rest.auth.oauth2.token-exchange.subject-token-type=urn:ietf:params:oauth:token-type:jwt

# Actor token settings
rest.auth.oauth2.token-exchange.actor-token=$ACTOR_TOKEN
rest.auth.oauth2.token-exchange.actor-token-type=urn:ietf:params:oauth:token-type:jwt
```

In this example, the subject and actor tokens are provided statically in the configuration. The
token exchange is performed using the primary IDP, which is configured using the
`rest.auth.oauth2.issuer-url` property.

### Using Dynamic Tokens

To enable dynamic fetching of tokens, the `rest.auth.oauth2.token-exchange.subject-token` and
`rest.auth.oauth2.token-exchange.actor-token` properties must _not_ be set.

Then, details for the subject and actor token fetch must be provided under the following prefixes,
respectively:

* `rest.auth.oauth2.token-exchange.subject-token.*`
* `rest.auth.oauth2.token-exchange.actor-token.*`

Any property that can be set under the `rest.auth.oauth2.` prefix can also be set under the above
prefixes, and will be used to configure a secondary agent for fetching the subject and actor
tokens.

> [!WARNING]
> The effective subject and actor token agent configuration will be the result of merging the
> subject-specific and actor-specific configuration with the main configuration.

This allows the AuthManager to support distinct configurations: a primary configuration for the
token exchange itself, and one or two secondary configurations, for the subject and actor token
fetches. This can even include using different IDPs for the token exchange and for fetching the
subject and actor tokens. (It is possible, however, to use the same IDP for both the token exchange
and for fetching the subject and actor tokens.)

Here is an example of how to configure the AuthManager to use a secondary IDP and different
credentials for fetching the subject token:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

# Basic settings
rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=token_exchange
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

# Subject token settings
rest.auth.oauth2.token-exchange.subject-token.issuer-url=https://$SECONDARY_IDP/realms/secondary
rest.auth.oauth2.token-exchange.subject-token.grant-type=device_code
rest.auth.oauth2.token-exchange.subject-token.client-id=Client2
rest.auth.oauth2.token-exchange.subject-token.client-secret=$CLIENT2_SECRET
rest.auth.oauth2.token-exchange.subject-token.scope=catalog2
```

In this example, the subject token is obtained from a secondary IDP using the `device_code` grant
type, thus allowing the user to authenticate with their own identity. The primary IDP is then used
to exchange the subject token for an access token using the token exchange grant type.

Here is a more complex example of how to configure the AuthManager to fetch both the subject and
actor tokens:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

# Basic settings
rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=token_exchange
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

# Subject token settings
rest.auth.oauth2.token-exchange.subject-token.issuer-url=https://$SECONDARY_IDP/realms/secondary
rest.auth.oauth2.token-exchange.subject-token.grant-type=authorization_code
rest.auth.oauth2.token-exchange.subject-token.scope=catalog2
rest.auth.oauth2.token-exchange.subject-token.client-id=Client2
rest.auth.oauth2.token-exchange.subject-token.client-secret=$CLIENT2_SECRET

# Actor token settings
rest.auth.oauth2.token-exchange.actor-token.grant-type=client_credentials
rest.auth.oauth2.token-exchange.actor-token.scope=catalog3
rest.auth.oauth2.token-exchange.actor-token.client-id=Client3
rest.auth.oauth2.token-exchange.actor-token.client-auth=private_key_jwt
rest.auth.oauth2.token-exchange.actor-token.client-assertion.jwt.private-key=/path/to/private_key.pem
```

In this example:

* The subject token is obtained from a secondary IDP using the `authorization_code` grant type (thus
  allowing the user to authenticate with their own identity) and distinct client credentials;

* The actor token is obtained from the primary IDP using the `client_credentials` grant type, with
  distinct client credentials and a private key JWT authentication method;

* The primary IDP is then used to exchange the subject and actor tokens for an access token using
  the token exchange grant type.

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
# Dremio AuthManager for Apache Iceberg - JWT Bearer Grant

## Overview

The Dremio AuthManager for Apache Iceberg supports the
[JWT Bearer Grant](https://datatracker.ietf.org/doc/html/rfc7523).

Assertions can be provided in two methods:

* Static assertions: assertions acquired externally and directly included in the configuration.
* Dynamic assertions: assertions are fetched dynamically by the AuthManager, using the same or
  different credentials and possibly a different IDP.

### Using Static Assertions

Static assertions are provided using the following properties:

* `rest.auth.oauth2.jwt-bearer.assertion`: the inline assertion value.
* `rest.auth.oauth2.jwt-bearer.assertion-file`: path to a file whose content (read and
  trimmed) is used as the assertion; ignored if `assertion` is set.

The assertion is taken from the inline `assertion` if set, otherwise from the file at
`assertion-file` if set, otherwise from dynamic configuration under `assertion.*`.

Here is an example of using a static assertion:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

rest.auth.oauth2.issuer-url=https://idp.example.com/realms/main
rest.auth.oauth2.grant-type=urn:ietf:params:oauth:grant-type:jwt-bearer
rest.auth.oauth2.client-id=my-client
rest.auth.oauth2.client-secret=s3cret
rest.auth.oauth2.scope=catalog

rest.auth.oauth2.jwt-bearer.assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature
```

### Using Dynamic Assertions

To enable dynamic fetching of assertions, the `rest.auth.oauth2.jwt-bearer.assertion` and
`rest.auth.oauth2.jwt-bearer.assertion-file` properties must _not_ be set.

Then, details for fetching the assertion must be provided under:

* `rest.auth.oauth2.jwt-bearer.assertion.*`

Any property that can be set under the `rest.auth.oauth2.` prefix can also be set under this
prefix, and will be used to configure a secondary agent for fetching the assertion.

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager

rest.auth.oauth2.issuer-url=https://$PRIMARY_IDP/realms/primary
rest.auth.oauth2.grant-type=urn:ietf:params:oauth:grant-type:jwt-bearer
rest.auth.oauth2.client-id=Client1
rest.auth.oauth2.client-secret=$CLIENT1_SECRET
rest.auth.oauth2.scope=catalog1

rest.auth.oauth2.jwt-bearer.assertion.issuer-url=https://$SECONDARY_IDP/realms/secondary
rest.auth.oauth2.jwt-bearer.assertion.grant-type=authorization_code
rest.auth.oauth2.jwt-bearer.assertion.client-id=Client2
rest.auth.oauth2.jwt-bearer.assertion.client-secret=$CLIENT2_SECRET
rest.auth.oauth2.jwt-bearer.assertion.scope=catalog2
```

For Microsoft Entra ID on-behalf-of requests, configure the assertion using one of the above
methods and add vendor-specific parameters with `rest.auth.oauth2.extra-params.*`, for example:

```properties
rest.auth.oauth2.extra-params.requested_token_use=on_behalf_of
```

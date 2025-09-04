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

> [!WARNING]
> This page is automatically generated from the code. Do not edit it manually.
> To update this page, run: `./gradlew generateDocs`.

## Overview

Dremio AuthManager for Apache Iceberg is highly configurable. The configuration is handled by
SmallRye Config, which supports a variety of configuration sources, including environment variables,
system properties, and configuration files.

By default, Dremio AuthManager loads its configuration from the catalog session properties, but it
can also load configuration from other sources, in the following order:

1. System properties (JVM options passed with `-D` arguments)
2. Environment variables
3. Catalog session properties (passed to the `OAuthManager` class at runtime by the `RESTCatalog`
   client)

Environment variables follow the naming conventions used by SmallRye Config; for example, the
property `rest.auth.oauth2.token-endpoint` can be set as `REST_AUTH_OAUTH2_TOKEN_ENDPOINT`, and so
on. See [SmallRye Config Environment
Variables](https://smallrye.io/smallrye-config/Main/config/environment-variables/) for more details.

### Enabling the AuthManager

To enable the Dremio AuthManager for Apache Iceberg, you need to set the `rest.auth.type` property
to `com.dremio.iceberg.authmgr.oauth2.OAuth2Manager` in your catalog configuration:

```properties
rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager
```

Note: this property _must_ be set in the catalog properties. Setting it as a system property or
environment variable will have no effect.

### Support for Local Configuration Files

Dremio AuthManager also supports loading configuration from local configuration files. This is
useful when you want to keep your credentials and other sensitive information out of your codebase.

To enable this feature, you need to set the `smallrye.config.locations` property to the path of your
configuration file. See [SmallRye Config
Locations](https://smallrye.io/smallrye-config/main/config-sources/locations/) for more details.

Note: the `smallrye.config.locations` property must be set as a system property or environment
variable; it will be ignored if set in the catalog properties.

If you need to load configuration from multiple files, you can specify a comma-separated list of
paths.



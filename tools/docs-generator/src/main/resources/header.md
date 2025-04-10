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


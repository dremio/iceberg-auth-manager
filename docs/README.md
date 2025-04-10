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
# Dremio AuthManager for Apache Iceberg - Documentation

## Overview

This project contains an implementation of Apache Iceberg's `AuthManager` API for OAuth2.

## Installation & Configuration

To install the Dremio AuthManager for Apache Iceberg, you can follow the instructions in the
[installation](./installation) section.

## Configuration

To enable this OAuth2 `AuthManager`, set the `rest.auth.type` configuration property to
`com.dremio.iceberg.authmgr.oauth2.OAuth2Manager`.

All configuration options are prefixed with `rest.auth.oauth2,`. See the
[Configuration](./configuration) section for a full list of configuration options.

## Impersonation & Delegation

The Dremio AuthManager for Apache Iceberg supports impersonation and delegation using the
token exchange grant type. See the [Impersonation & Delegation](./impersonation) section for more
details on how to configure impersonation and delegation.

## Dialects

Two "dialects" of OAuth2 are supported:

- `standard`: this dialect is based on the OAuth2 standard, as defined
  in [RFC 6749](https://tools.ietf.org/html/rfc6749) and other RFCs.
- `iceberg_rest`: this dialect reproduces the behavior of Iceberg REST's built-in OAuth2
  `AuthManager` and exhibits some non-standard behavior.

For more details on the differences between the two dialects, see the [Dialects](./dialects)
section.

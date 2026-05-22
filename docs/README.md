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

## Installation

Dremio Iceberg AuthManager is available as a Maven artifact from
[Maven Central](https://central.sonatype.com/namespace/com.dremio.iceberg.authmgr).
You can also download the latest version from the
[GitHub Releases page](https://github.com/adutra/iceberg-auth-manager/releases).

Follow the instructions in the [Installation](./installation.md) section to get started.

## Usage

To use the Dremio AuthManager for Apache Iceberg, follow the instructions for the platform you are 
using:

* [Apache Spark](./spark.md)
* [Apache Flink](./flink.md)
* [Apache Kafka](./kafka.md)

## Configuration

To enable this OAuth2 `AuthManager`, set the `rest.auth.type` configuration property to
`com.dremio.iceberg.authmgr.oauth2.OAuth2Manager`.

Configuration options can be passed via catalog properties, but also via system properties,
environment variables, or configuration files. See the [Configuration](./configuration.md) section
for a full list of configuration options.

## Client Authentication

The Dremio AuthManager for Apache Iceberg supports several client authentication methods. See the
[Client Authentication](./client-authentication.md) section for more details on how to configure
client authentication.

## Grant Types

The Dremio AuthManager for Apache Iceberg supports several OAuth2 grant types:

* Client Credentials Grant ([RFC 6749, Section 4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4))
* Authorization Code Grant ([RFC 6749, Section 4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1))
* Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))
* [Token Exchange Grant](./token-exchange.md) ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))
* [JWT Bearer Grant](./jwt-bearer.md) ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523))

The Dremio AuthManager also supports the Resource Owner Password Credentials Grant 
([RFC 6749, Section 4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)), but this grant 
type is deprecated and should be avoided if possible.

See the [Configuration](./configuration.md) section for more details on how to configure grant 
types.

### Impersonation & Delegation

The Dremio AuthManager for Apache Iceberg supports impersonation and delegation using the token
exchange grant type. See the [Token Exchange](./token-exchange.md) section for more details on how
to configure impersonation and delegation.

### Assertion Grants

The Dremio AuthManager for Apache Iceberg supports JWT assertion grants with static or dynamic
assertions. See the [JWT Bearer Grant](./jwt-bearer.md) section for more details.

## Sender-Constrained Access Tokens (DPoP)

The Dremio AuthManager for Apache Iceberg supports
[Demonstrating Proof of Possession (DPoP)](./dpop.md)
([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)), which binds access tokens to an
asymmetric keypair held by the client so that stolen tokens cannot be replayed. DPoP is opt-in; see
the [DPoP](./dpop.md) section for details on how to enable and configure it.

## Migration From Iceberg's Built-In OAuth2 `AuthManager`

Migrating from Iceberg's built-in OAuth2 `AuthManager` to the Dremio AuthManager for Apache Iceberg
is easy, but may require some configuration changes. See the [Migration](./migration.md) section for
more details.

## Developer Documentation

See the [Developer Documentation](./developer/README.md) for more details on the internal
architecture and implementation of the Dremio AuthManager for Apache Iceberg.

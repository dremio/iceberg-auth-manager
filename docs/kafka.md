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
# Dremio AuthManager for Apache Iceberg - Usage with Apache Iceberg Sink Connector for Kafka Connect

## Prerequisites

* Apache Iceberg 1.9.1 or later is required.
* Dremio AuthManager for Apache Iceberg 0.1.0 or later is required.
* Apache Iceberg Sink Connector for Kafka Connect requires Java 17 or later for runtime.

## Preparing the Connector

To use the Dremio AuthManager for Apache Iceberg with the Iceberg Kafka Sink Connector, you need to
repackage the connector bundle with the Dremio AuthManager for Apache Iceberg runtime jar.

The jar to use is `com.dremio.iceberg.authmgr:authmgr-oauth2-standalone`. This jar does
not relocate Iceberg packages, and is the only one suitable for use in conjunction with the Iceberg
Kafka Sink Connector.

### Using a Dockerfile

The following Dockerfile can be used to build a custom Kafka Connect image with the Iceberg Kafka
Sink Connector and the Dremio AuthManager for Apache Iceberg:

```dockerfile
# Use the base Kafka Connect image
FROM confluentinc/cp-kafka-connect:latest

ARG ICEBERG_CONNECTOR_VERSION
ARG AUTHMGR_VERSION
ARG MAVEN_REPO=https://repo1.maven.org/maven2

# Install the Iceberg Kafka Sink Connector
RUN confluent-hub install --no-prompt iceberg/iceberg-kafka-connect:$ICEBERG_CONNECTOR_VERSION

# Download the Dremio AuthManager for Apache Iceberg standalone jar
RUN curl -L $MAVEN_REPO/com/dremio/iceberg/authmgr/authmgr-oauth2-standalone/$AUTHMGR_VERSION/authmgr-oauth2-standalone-$AUTHMGR_VERSION.jar \
    -o /usr/share/confluent-hub-components/iceberg-iceberg-kafka-connect/lib/authmgr-oauth2-standalone-$AUTHMGR_VERSION.jar

# Set up the plugin path
ENV CONNECT_PLUGIN_PATH="/usr/share/confluent-hub-components"

# Expose the necessary ports
EXPOSE 8083
```

You can then build and run the image using the following commands:

```shell
docker build \
  --build-arg ICEBERG_CONNECTOR_VERSION=[REPLACE_WITH_VERSION] \
  --build-arg AUTHMGR_VERSION=[REPLACE_WITH_VERSION] \
  -t kafka-connect-dremio-authmgr
docker run -p 8083:8083 kafka-connect-dremio-authmgr
```

Note: more environment variables may be required to run the container, depending on your Kafka
Connect setup, e.g. for configuring the Kafka cluster to connect to (`CONNECT_BOOTSTRAP_SERVERS`).

### Rebuilding from Source

Checkout the Iceberg source code and the desired version:

```shell
export ICEBERG_VERSION=1.10.0
git clone https://github.com/apache/iceberg.git
cd iceberg
git checkout apache-iceberg-$ICEBERG_VERSION
```

Open the `kafka-connect/build.gradle` file and patch the
`:iceberg-kafka-connect:iceberg-kafka-connect-runtime` project; under `dependencies`, add the
following line to include the Dremio AuthManager for Apache Iceberg:

```groovy
implementation 'com.dremio.iceberg.authmgr:authmgr-oauth2-standalone:[REPLACE_WITH_VERSION]'
```

Then build the connector:

```shell
./gradlew -x test -x integrationTest clean build
```

### Repackaging a Pre-built Connector

Alternatively, you can download a pre-built connector, for example from [Confluent Hub], and
repackage it with the Dremio AuthManager for Apache Iceberg jar.

For example, the following commands install the Iceberg Kafka Sink Connector from Confluent Hub 
locally and then add the Dremio AuthManager for Apache Iceberg jar to its `lib` directory:

```shell
# download the connector
confluent-hub install --no-prompt iceberg/iceberg-kafka-connect:[REPLACE_WITH_VERSION]

# download Dremio AuthManager for Apache Iceberg
wget https://repo1.maven.org/maven2/com/dremio/iceberg/authmgr/authmgr-oauth2-standalone/[REPLACE_WITH_VERSION]/authmgr-oauth2-standalone-[REPLACE_WITH_VERSION].jar

# move the Dremio AuthManager for Apache Iceberg jar to the connector's lib directory
mv authmgr-oauth2-standalone-[REPLACE_WITH_VERSION].jar /usr/share/confluent-hub-components/iceberg-iceberg-kafka-connect/lib/
```

[Confluent Hub]: https://www.confluent.io/hub/iceberg/iceberg-kafka-connect

## Configuring the Connector

Dremio AuthManager for Apache Iceberg is configured using the `iceberg.catalog.*` properties. For
example:

```properties
iceberg.catalog.rest.auth.type=com.dremio.iceberg.authmgr.oauth2.OAuth2Manager
iceberg.catalog.rest.auth.oauth2.client-id=your-client-id
iceberg.catalog.rest.auth.oauth2.client-secret=your-client-secret
iceberg.catalog.rest.auth.oauth2.issuer-url=https://keycloak.example.com/realms/master
iceberg.catalog.rest.auth.oauth2.scope=catalog
```

See the [configuration](./configuration.md) section for a full list of configuration options.

For more details on configuring the Iceberg Kafka Sink Connector, see the [Iceberg Kafka Connect
Documentation].

[Iceberg Kafka Connect Documentation]: https://iceberg.apache.org/docs/latest/kafka-connect/


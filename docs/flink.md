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
# Dremio AuthManager for Apache Iceberg - Usage with Flink

## Prerequisites

* Iceberg 1.9.0 or later is required.
* Dremio AuthManager for Apache Iceberg requires Java 11 or later for runtime.
* Dremio AuthManager for Apache Iceberg is meant to be used in conjunction with an Iceberg engine
  runtime jar, e.g. `iceberg-flink-runtime-1.20`.

## Preparation

First, download the required JAR files. You'll need:

1. **Iceberg Flink Runtime JAR**: Download from [Maven Central](https://repo1.maven.org/maven2/org/apache/iceberg/iceberg-flink-runtime-1.20/)
2. **Hadoop JAR**: Download from [Apache Hadoop](https://archive.apache.org/dist/hadoop/common/)
2. **AuthManager Runtime JAR**: Download from [Maven Central](https://repo1.maven.org/maven2/com/dremio/iceberg/authmgr/authmgr-oauth2/) or the [GitHub Releases page](https://github.com/dremio/iceberg-auth-manager/releases)

```shell
# Download Iceberg Flink Runtime JAR
ICEBERG_VERSION=1.9.1
FLINK_VERSION_MAJOR=1.20
MAVEN_URL=https://repo1.maven.org/maven2
ICEBERG_MAVEN_URL=${MAVEN_URL}/org/apache/iceberg
ICEBERG_PACKAGE=iceberg-flink-runtime
wget ${ICEBERG_MAVEN_URL}/${ICEBERG_PACKAGE}-${FLINK_VERSION_MAJOR}/${ICEBERG_VERSION}/${ICEBERG_PACKAGE}-${FLINK_VERSION_MAJOR}-${ICEBERG_VERSION}.jar

# Download Hadoop JAR
APACHE_HADOOP_URL=https://archive.apache.org/dist/hadoop/
HADOOP_VERSION=2.8.5
wget ${APACHE_HADOOP_URL}/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}.tar.gz
tar xzvf hadoop-${HADOOP_VERSION}.tar.gz
HADOOP_HOME=`pwd`/hadoop-${HADOOP_VERSION}
export HADOOP_CLASSPATH=`$HADOOP_HOME/bin/hadoop classpath`

# Download AuthManager Runtime JAR
AUTHMGR_VERSION=[REPLACE_WITH_VERSION]
AUTHMGR_MAVEN_URL=${MAVEN_URL}/com/dremio/iceberg/authmgr
wget ${AUTHMGR_MAVEN_URL}/authmgr-oauth2-runtime/${AUTHMGR_VERSION}/authmgr-oauth2-runtime-${AUTHMGR_VERSION}.jar
```

## Using Flink SQL Client

Place required JAR files in Flink's `lib/` directory to make them available globally:

```shell
cp iceberg-flink-runtime-1.20-1.9.1.jar $FLINK_HOME/lib/
cp authmgr-oauth2-runtime-[REPLACE_WITH_VERSION].jar $FLINK_HOME/lib/
```

Now you can start the Flink SQL Client:

```shell
./bin/sql-client.sh embedded shell
```

## Catalog Configuration

Once the JARs are available in the classpath, you can create an Iceberg catalog in Flink that uses 
the Dremio AuthManager.

Here is an example for a simple OAuth2 client credentials flow with an external authorization 
server:

```sql
CREATE CATALOG iceberg_rest_catalog WITH (
  'type' = 'iceberg',
  'catalog-type' = 'rest',
  'uri' = 'https://catalog.example.com/api/catalog',
  'warehouse' = 'your-warehouse-name',
  'rest.auth.type' = 'com.dremio.iceberg.authmgr.oauth2.OAuth2Manager',
  'rest.auth.oauth2.client-id' = 'your-client-id',
  'rest.auth.oauth2.client-secret' = 'your-client-secret',
  'rest.auth.oauth2.issuer-url' = 'https://keycloak.example.com/realms/master',
  'rest.auth.oauth2.scope' = 'catalog'
);
```

Here is an example of compatibility with Iceberg's built-in OAuth2 manager, assuming the catalog
server is Apache Polaris:

```sql
CREATE CATALOG iceberg_rest_catalog WITH (
  'type' = 'iceberg',
  'catalog-type' = 'rest',
  'uri' = 'https://polaris.example.com/api/catalog',
  'warehouse' = 'your-warehouse-name',
  'rest.auth.type' = 'com.dremio.iceberg.authmgr.oauth2.OAuth2Manager',
  'rest.auth.oauth2.dialect' = 'iceberg_rest',
  'rest.auth.oauth2.client-id' = 'your-client-id',
  'rest.auth.oauth2.client-secret' = 'your-client-secret',
  'rest.auth.oauth2.scope' = 'PRINCIPAL_ROLE:ALL'
);
```

See the [configuration](./configuration.md) section for more details on how to configure the Dremio 
AuthManager for Apache Iceberg.

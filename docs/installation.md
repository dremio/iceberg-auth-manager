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
# Dremio AuthManager for Apache Iceberg - Installation

## Download

The Dremio AuthManager for Apache Iceberg is available as a jar which you can download from the
[Releases page](https://github.com/dremio/iceberg-auth-manager/releases).

You should choose the `runtime` jar, e.g. `authmgr-oauth2-x.y.z-runtime.jar`.

## Prerequisites

* Iceberg Core 1.9.0 or later is required.
* Dremio AuthManager for Apache Iceberg requires Java 11 or later for runtime.
* Dremio AuthManager for Apache Iceberg is meant to be used in conjunction with an Iceberg engine
  runtime jar, e.g. `iceberg-spark-runtime-3.5_2.12` or `iceberg-flink-runtime-1.20`.

## Usage with Spark

To use the Dremio AuthManager for Apache Iceberg with Spark, you need to add the jar to your Spark
classpath. You can do this by adding the jar to the `--jars` option when starting Spark, or by
adding it to the `spark.jars` configuration property in your Spark configuration file.

For example, if you are using the `spark-shell`, you can start it with the following command:

```shell
spark-shell \
  --packages org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.9.0 \
  --jars /path/to/authmgr-oauth2-x.y.z-runtime.jar
```

Similarly, if you are using Spark SQL, you can start it with the following command:

```shell
spark-sql  \
  --packages org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.9.0 \
  --jars /path/to/authmgr-oauth2-x.y.z-runtime.jar
```

You can also add the jar to your spark-defaults.conf file:

```
spark.jars /path/to/authmgr-oauth2-x.y.z-runtime.jar
```

Once the jar is added to the classpath, you can use the Dremio AuthManager for Apache Iceberg in
your Spark applications. See the [configuration](./configuration.md) section for more details on how
to configure the Dremio AuthManager for Apache Iceberg.

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

## Overview

The Dremio AuthManager for Apache Iceberg can be obtained from various sources, including
Maven Central and GitHub Releases. You can choose the method that best fits your needs.

### Maven Artifacts

Maven artifacts are published to 
[Maven Central](https://central.sonatype.com/namespace/com.dremio.iceberg.authmgr).

If you intend to simply download the artifacts for usage with Spark or other
engines, make sure to download the `authmgr-oauth2-runtime` artifact. This
artifact contains all the dependencies required to run the Dremio AuthManager
for Apache Iceberg in Spark or other engines.

Instead, if you are developing a Java application and need to include the Dremio
AuthManager for Apache Iceberg as a dependency, you should use the
`authmgr-oauth2-core` artifact:

#### Maven Dependency

```xml
<dependencies>
  <dependency>
    <groupId>com.dremio.iceberg.authmgr</groupId>
    <artifactId>authmgr-oauth2-core</artifactId>
    <version>[REPLACE_WITH_VERSION]</version>
  </dependency>
</dependencies>
```

#### Gradle Dependency

```kotlin
dependencies {
  implementation("com.dremio.iceberg.authmgr:authmgr-oauth2-core:[REPLACE_WITH_VERSION]")
}
```

### Direct Download

Alternatively, you can download pre-built jars directly from the
[Releases page](https://github.com/dremio/iceberg-auth-manager/releases).

Again, if you intend to simply download the artifacts for usage with Spark or other
engines, make sure to download the `authmgr-oauth2-runtime` artifact.

### Building from Source

You can build the code source and publish artifacts to your local Maven repository 
(`~/.m2/repository`) using the following command:

```bash
./gradlew clean build publishToMavenLocal
```

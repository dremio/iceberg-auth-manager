/*
 * Copyright (C) 2025 Dremio Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
  id("authmgr-java")
  id("authmgr-java-testing")
}

description = "Spark tests for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Spark Tests") }

dependencies {

  // Note: iceberg-core will be provided by the iceberg-spark-runtime jar,
  // with shaded dependencies; it should not leak into this project unshaded.

  intTestImplementation(project(":authmgr-oauth2-runtime"))

  intTestImplementation(testFixtures(project(":authmgr-oauth2-core")) as ModuleDependency) {
    exclude(group = "org.apache.iceberg")
  }

  intTestImplementation(platform(libs.iceberg.bom))
  intTestImplementation("org.apache.iceberg:iceberg-spark-runtime-3.5_2.12")
  intTestImplementation("org.apache.iceberg:iceberg-spark-extensions-3.5_2.12")

  intTestImplementation(libs.spark.sql)

  intTestRuntimeOnly("org.apache.iceberg:iceberg-aws")
  intTestRuntimeOnly("org.apache.iceberg:iceberg-aws-bundle")

  intTestImplementation(platform(libs.testcontainers.bom))
  intTestImplementation("org.testcontainers:testcontainers")
  intTestImplementation(libs.s3mock.testcontainers)

  intTestImplementation(platform(libs.junit.bom))
  intTestImplementation("org.junit.jupiter:junit-jupiter")
  intTestImplementation("org.junit.jupiter:junit-jupiter-api")

  intTestImplementation(libs.assertj.core)
  intTestImplementation(libs.mockito.core)
}

tasks.named<Test>("intTest").configure {
  if (System.getenv("CI") == null) {
    maxParallelForks = 2
  }
  dependsOn(":authmgr-oauth2-runtime:shadowJar")
  environment("AWS_REGION", "us-west-2")
  environment("AWS_ACCESS_KEY_ID", "fake")
  environment("AWS_SECRET_ACCESS_KEY", "fake")
  jvmArgs("--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED")
}

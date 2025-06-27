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
  id("authmgr-maven")
}

description = "Core OAuth2 implementation for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Core") }

dependencies {
  implementation(platform(libs.iceberg.bom))
  implementation("org.apache.iceberg:iceberg-api")
  implementation("org.apache.iceberg:iceberg-core")

  implementation(libs.auth0.jwt)

  implementation(libs.slf4j.api)
  implementation(libs.caffeine)

  implementation(platform(libs.jackson.bom))
  implementation("com.fasterxml.jackson.core:jackson-annotations")
  implementation("com.fasterxml.jackson.core:jackson-core")
  implementation("com.fasterxml.jackson.core:jackson-databind")

  compileOnly(libs.jakarta.annotation.api)
  compileOnly(libs.errorprone.annotations)

  compileOnly(project(":authmgr-immutables"))
  annotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testFixturesApi(platform(libs.iceberg.bom))
  testFixturesApi("org.apache.iceberg:iceberg-api")
  testFixturesApi("org.apache.iceberg:iceberg-core")

  testFixturesApi(platform(libs.junit.bom))
  testFixturesApi("org.junit.jupiter:junit-jupiter")

  testFixturesApi(platform(libs.jackson.bom))
  testFixturesApi("com.fasterxml.jackson.core:jackson-core")
  testFixturesApi("com.fasterxml.jackson.core:jackson-databind")

  testFixturesApi(libs.assertj.core)
  testFixturesApi(libs.mockito.core)

  testFixturesApi(libs.auth0.jwt)

  testFixturesApi(libs.bouncycastle.bcpkix)

  testFixturesApi(libs.mockserver.netty)
  testFixturesApi(libs.mockserver.client.java)

  testFixturesApi(platform(libs.testcontainers.bom))
  testFixturesApi("org.testcontainers:testcontainers")
  testFixturesApi("org.testcontainers:junit-jupiter")
  testFixturesApi(libs.keycloak.admin.client)
  testFixturesApi(libs.testcontainers.keycloak)

  testFixturesCompileOnly(project(":authmgr-immutables"))
  testFixturesAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testImplementation(libs.auth0.jwt)
  testCompileOnly(libs.jakarta.annotation.api)

  testCompileOnly(project(":authmgr-immutables"))
  testAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  intTestImplementation(libs.auth0.jwt)

  intTestCompileOnly(project(":authmgr-immutables"))
  intTestAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))
}

tasks.named<Test>("test").configure {
  if (System.getenv("CI") == null) {
    maxParallelForks = 4
  }
}

tasks.named<Test>("intTest").configure {
  if (System.getenv("CI") == null) {
    maxParallelForks = 2
  }
  systemProperty("authmgr.it.long.total", System.getProperty("authmgr.it.long.total", "PT30S"))
  useJUnitPlatform {
    project.findProperty("includeTags")?.let { includeTags = (it as String).split(',').toSet() }
    project.findProperty("excludeTags")?.let { excludeTags = (it as String).split(',').toSet() }
  }
}

val mockitoAgent = configurations.create("mockitoAgent")

dependencies {
  testImplementation(libs.mockito.core)
  testImplementation(libs.logback.classic)
  mockitoAgent(libs.mockito.core) { isTransitive = false }
}

tasks { test { jvmArgs("-javaagent:${mockitoAgent.asPath}") } }

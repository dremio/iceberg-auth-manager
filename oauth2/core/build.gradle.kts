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
  id("authmgr-java-production")
  id("authmgr-java-testing")
  id("authmgr-maven")
}

description = "Core OAuth2 implementation for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Core") }

dependencies {
  api(platform(libs.iceberg.bom))
  api("org.apache.iceberg:iceberg-api")
  api("org.apache.iceberg:iceberg-core")

  api(project(":oauth2-agent"))

  compileOnly(project(":authmgr-immutables"))
  annotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testFixturesApi(testFixtures(project(":oauth2-agent")))

  testFixturesApi(platform(libs.iceberg.bom))
  testFixturesApi("org.apache.iceberg:iceberg-api")
  testFixturesApi("org.apache.iceberg:iceberg-core")

  testFixturesImplementation(libs.mockserver.netty)
  testFixturesImplementation(libs.mockserver.client.java)

  testFixturesCompileOnly(project(":authmgr-immutables"))
  testFixturesAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testCompileOnly(libs.jakarta.annotation.api)

  testImplementation(libs.caffeine)
  testImplementation(libs.mockserver.netty)
  testImplementation(libs.mockserver.client.java)

  testCompileOnly(project(":authmgr-immutables"))
  testAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))
}

val mockitoAgent = configurations.create("mockitoAgent")

dependencies { mockitoAgent(libs.mockito.core) { isTransitive = false } }

tasks { test { jvmArgs("-javaagent:${mockitoAgent.asPath}") } }

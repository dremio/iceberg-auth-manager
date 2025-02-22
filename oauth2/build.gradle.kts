/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
  id("authmgr-java")
  id("authmgr-shadow-jar")
}

dependencies {
  implementation(enforcedPlatform(libs.iceberg.bom))
  implementation("org.apache.iceberg:iceberg-api")
  implementation("org.apache.iceberg:iceberg-core")

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
  testFixturesApi(libs.mockserver.netty)
  testFixturesApi(libs.mockserver.client.java)

  testFixturesCompileOnly(project(":authmgr-immutables"))
  testFixturesAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testImplementation(libs.auth0.jwt)
  testCompileOnly(libs.jakarta.annotation.api)

  testCompileOnly(project(":authmgr-immutables"))
  testAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  intTestImplementation(platform(libs.testcontainers.bom))
  intTestImplementation("org.testcontainers:testcontainers")
  intTestImplementation("org.testcontainers:junit-jupiter")
  intTestImplementation(libs.auth0.jwt)
  intTestImplementation(libs.keycloak.admin.client)
  intTestImplementation(libs.testcontainers.keycloak) {
    exclude(group = "org.slf4j") // uses SLF4J 2.x, we are not ready yet
  }

  intTestCompileOnly(project(":authmgr-immutables"))
  intTestAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))
}

tasks.named<Test>("test").configure { maxParallelForks = 4 }

tasks.named<Test>("intTest").configure {
  maxParallelForks = 2
  systemProperty("authmgr.it.long.total", System.getProperty("authmgr.it.long.total", "PT30S"))
}

tasks.withType<ShadowJar> {
  // all dependencies are expected to be provided by Iceberg runtime jars
  configurations = emptyList()
  // relocate to same package as in Iceberg runtime jars
  relocate("com.fasterxml.jackson", "org.apache.iceberg.shaded.com.fasterxml.jackson")
  relocate("com.github.benmanes", "org.apache.iceberg.shaded.com.github.benmanes")
}

val mockitoAgent = configurations.create("mockitoAgent")

dependencies {
  testImplementation(libs.mockito.core)
  mockitoAgent(libs.mockito.core) { isTransitive = false }
}

tasks { test { jvmArgs("-javaagent:${mockitoAgent.asPath}") } }

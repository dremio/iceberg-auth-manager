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

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

plugins {
  id("authmgr-java")
  id("authmgr-java-testing")
  id("authmgr-maven")
}

description = "Core OAuth2 implementation for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Core") }

val docs by
  configurations.creating {
    description = "Dependencies for generating configuration documentation"
    isCanBeResolved = true
    isCanBeConsumed = false
    isVisible = false
  }

dependencies {
  implementation(platform(libs.iceberg.bom))
  implementation("org.apache.iceberg:iceberg-api")
  implementation("org.apache.iceberg:iceberg-core")

  implementation(libs.nimbus.oauth2.oidc.sdk) {
    exclude(group = "com.github.stephenc.jcip", module = "jcip-annotations")
  }
  implementation(libs.nimbus.jose.jwt)

  implementation(libs.httpclient5)

  implementation(libs.slf4j.api)
  implementation(libs.caffeine)

  compileOnly(libs.jakarta.annotation.api)
  compileOnly(libs.errorprone.annotations)

  compileOnly(project(":authmgr-immutables"))
  annotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  testFixturesApi(platform(libs.iceberg.bom))
  testFixturesApi("org.apache.iceberg:iceberg-api")
  testFixturesApi("org.apache.iceberg:iceberg-core")

  testFixturesApi(platform(libs.junit.bom))
  testFixturesApi("org.junit.jupiter:junit-jupiter")
  testFixturesApi(libs.junit.pioneer)

  testFixturesApi(libs.assertj.core)
  testFixturesApi(libs.mockito.core)

  testFixturesApi(libs.nimbus.oauth2.oidc.sdk)
  testFixturesApi(libs.nimbus.jose.jwt)

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

  testCompileOnly(libs.jakarta.annotation.api)

  testCompileOnly(project(":authmgr-immutables"))
  testAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  intTestCompileOnly(project(":authmgr-immutables"))
  intTestAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  longTestCompileOnly(project(":authmgr-immutables"))
  longTestAnnotationProcessor(project(":authmgr-immutables", configuration = "processor"))

  docs("com.thoughtworks.qdox:qdox:2.2.0")
}

tasks.named<Test>("test").configure {
  configForks(4)
  commonTestConfig()
}

tasks.named<Test>("intTest").configure {
  configForks(3)
  commonTestConfig()
}

tasks.named<Test>("longTest").configure {
  configForks(3)
  commonTestConfig()
  if (System.getProperty("authmgr.it.long.total") != null) {
    val total = Duration.parse(System.getProperty("authmgr.it.long.total"))
    systemProperty("authmgr.it.long.total", total.toIsoString())
    // Add a 10-second safety window to the tests default timeout
    systemProperty(
      "junit.jupiter.execution.timeout.testable.method.default",
      (total + 10.seconds).inWholeSeconds.toString() + " s",
    )
  }
}

val mockitoAgent = configurations.create("mockitoAgent")

dependencies {
  testImplementation(libs.mockito.core)
  testImplementation(libs.logback.classic)
  mockitoAgent(libs.mockito.core) { isTransitive = false }
}

tasks { test { jvmArgs("-javaagent:${mockitoAgent.asPath}") } }

fun Test.configForks(forks: Int) {
  if (System.getenv("CI") == null) {
    maxParallelForks = forks
  }
}

fun Test.commonTestConfig() {
  val outputMemoryUsage = System.getProperty("authmgr.test.mockserver.outputMemoryUsage")
  if (outputMemoryUsage.toBoolean()) {
    val outputDir =
      project.layout.buildDirectory.dir("reports/mockserver/${this.name}").get().asFile.absolutePath
    outputs.dir(outputDir)
    File(outputDir).mkdirs()
    systemProperty("authmgr.test.mockserver.memoryUsageCsvDirectory", outputDir)
  }
}

sourceSets.create("docs") {
  java.srcDir("src/docs/java")
  resources.srcDir("src/docs/resources")
  compileClasspath += docs
  runtimeClasspath += docs
}

tasks.named("processDocsResources", ProcessResources::class) {
  duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.register<JavaExec>("generateDocs") {
  group = "documentation"
  description = "Generates configuration documentation from OAuth2Properties"
  mainClass.set("com.dremio.iceberg.authmgr.oauth2.docs.DocumentationGenerator")
  classpath = sourceSets.getByName("docs").runtimeClasspath

  val inputFile =
    project.file("src/main/java/com/dremio/iceberg/authmgr/oauth2/OAuth2Properties.java")
  val outputFile = rootProject.file("docs/configuration.md")

  val headerFile = sourceSets.getByName("docs").resources.singleFile
  val header = headerFile.readText()

  inputs.files(inputFile, headerFile)
  outputs.file(outputFile)

  args(
    inputFile.absolutePath,
    "com.dremio.iceberg.authmgr.oauth2.OAuth2Properties",
    header,
    outputFile.absolutePath,
  )

  doFirst { outputFile.parentFile.mkdirs() }
}

tasks.named("publish") { dependsOn("generateDocs") }

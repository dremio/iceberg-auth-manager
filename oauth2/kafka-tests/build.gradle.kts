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

import org.gradle.api.plugins.jvm.JvmTestSuite
import org.gradle.kotlin.dsl.register

plugins {
  id("authmgr-java")
  id("authmgr-java-testing")
}

// Override Java version for this module to support Kafka 4.0.0+
tasks.withType<JavaCompile>().configureEach { options.release.set(17) }

java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }

// Configure all test tasks to use Java 17
tasks.withType<Test>().configureEach {
  javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(17)) })
}

description = "Kafka Sink Connector tests for Dremio AuthManager for Apache Iceberg"

// Matrix testing configuration
val icebergConnectorVersions =
  project.findProperty("authmgr.test.iceberg-connector.versions").toString().split(",")

val kafkaCpVersions =
  project
    .findProperty("authmgr.test.kafka-cp.versions")
    .toString()
    .split(",")
    .map { it.split("/") }
    .associate { it[0] to it[1] }

// Use the last combination as default for regular intTest
val defaultIcebergConnectorVersion = icebergConnectorVersions.last()
val defaultKafkaVersion = kafkaCpVersions.keys.last()
val defaultCpVersion = kafkaCpVersions.values.last()

val intTestBase =
  configurations.create("intTestBase") {
    description =
      "Base configuration holding common dependencies for Iceberg Kafka Connector integration tests"
    isCanBeResolved = false
    isCanBeConsumed = false
  }

// Make intTestImplementation extend from intTestBase
configurations.intTestImplementation.get().extendsFrom(intTestBase)

dependencies {
  intTestBase(project(":authmgr-oauth2-standalone"))

  intTestBase(testFixtures(project(":authmgr-oauth2-core")) as ModuleDependency)

  intTestBase(platform(libs.testcontainers.bom))
  intTestBase("org.testcontainers:testcontainers")
  intTestBase("org.testcontainers:kafka")
  intTestBase(libs.s3mock.testcontainers)

  intTestBase(platform(libs.junit.bom))
  intTestBase("org.junit.jupiter:junit-jupiter")
  intTestBase("org.junit.jupiter:junit-jupiter-api")
  intTestBase("org.junit.platform:junit-platform-launcher")

  intTestBase(libs.httpclient5)

  intTestBase(libs.assertj.core)
  intTestBase(libs.mockito.core)
  intTestBase(libs.awaitility)
  intTestBase(libs.logback.classic)

  // Add to intTestImplementation all Iceberg/Kafka dependencies (with default versions)
  // that are required for compilation of test classes
  intTestImplementation("org.apache.kafka:kafka-clients:$defaultKafkaVersion")
  intTestImplementation("org.apache.kafka:connect-api:$defaultKafkaVersion")
  intTestImplementation("org.apache.kafka:connect-json:$defaultKafkaVersion")
  intTestImplementation("org.apache.kafka:connect-runtime:$defaultKafkaVersion")
}

// Create matrix test tasks for each version combination
val matrixTestTasks = mutableListOf<TaskProvider<Test>>()

icebergConnectorVersions.forEach { icebergConnectorVersion ->
  kafkaCpVersions.forEach { kafkaCpVersion ->
    val kafkaVersion = kafkaCpVersion.key
    val cpVersion = kafkaCpVersion.value

    val suiteName = suiteName(icebergConnectorVersion, kafkaVersion, cpVersion)

    val runtimeConfig =
      configurations.create(suiteName) {
        extendsFrom(intTestBase)
        isCanBeResolved = true
        isCanBeConsumed = false
      }

    // Add version-specific dependencies
    dependencies {
      runtimeConfig(platform("org.apache.iceberg:iceberg-bom:$icebergConnectorVersion"))
      runtimeConfig("org.apache.kafka:kafka-clients:$kafkaVersion")
      runtimeConfig("org.apache.kafka:connect-api:$kafkaVersion")
      runtimeConfig("org.apache.kafka:connect-json:$kafkaVersion")
      runtimeConfig("org.apache.kafka:connect-runtime:$kafkaVersion")
      runtimeConfig("org.apache.iceberg:iceberg-aws:$icebergConnectorVersion")
      runtimeConfig("org.apache.iceberg:iceberg-aws-bundle:$icebergConnectorVersion")
    }

    testing {
      suites {
        register<JvmTestSuite>(suiteName) {
          targets.all {
            testTask.configure {
              shouldRunAfter("test")

              if (System.getenv("CI") == null) {
                maxParallelForks = 2
              }

              description =
                "Runs Kafka integration tests with Iceberg $icebergConnectorVersion, " +
                  "Kafka $kafkaVersion and Confluent Platform $cpVersion."

              // Use shared test classes from src/intTest
              testClassesDirs = sourceSets.intTest.get().output.classesDirs
              classpath = runtimeConfig + sourceSets.intTest.get().output

              dependsOn(":authmgr-oauth2-standalone:shadowJar")

              // Get the absolute path of the authmgr-oauth2-standalone jar
              val standaloneProject = project(":authmgr-oauth2-standalone")
              val authmgrStandaloneJar =
                standaloneProject.layout.buildDirectory
                  .file("libs/${standaloneProject.name}-${rootProject.version}.jar")
                  .get()
                  .asFile
                  .absolutePath

              // Set system properties to identify the versions being tested
              systemProperty("authmgr.test.iceberg-connector.version", icebergConnectorVersion)
              systemProperty("authmgr.test.kafka.version", kafkaVersion)
              systemProperty("authmgr.test.cp.version", cpVersion)
              systemProperty("authmgr.test.authmgr-standalone-jar", authmgrStandaloneJar)

              inputs.property("icebergConnectorVersion", icebergConnectorVersion)
              inputs.property("kafkaVersion", kafkaVersion)
              inputs.property("cpVersion", cpVersion)
              inputs.property("authmgrStandaloneJar", authmgrStandaloneJar)
            }
            matrixTestTasks.add(testTask)
          }
        }
      }
    }
  }
}

tasks.named<Test>("intTest").configure {
  dependsOn(
    tasks.named(suiteName(defaultIcebergConnectorVersion, defaultKafkaVersion, defaultCpVersion))
  )
  // the task itself should not run any tests
  enabled = false
  description =
    "Runs Kafka integration tests with the default Iceberg version ($defaultIcebergConnectorVersion), " +
      "the default Kafka version ($defaultKafkaVersion) " +
      "and the default Confluent Platform version ($defaultCpVersion)."
}

// Create a task to run all matrix tests
tasks.register("intTestMatrix") {
  group = "verification"
  description = "Runs all integration test matrix combinations."
  dependsOn(matrixTestTasks)
}

// Helper task to print matrix configuration
tasks.register("printTestMatrix") {
  group = "help"
  description = "Prints the test matrix configuration."
  doLast {
    println("Kafka Iceberg Connector Integration Test Matrix:")
    println("Iceberg Connection versions: ${icebergConnectorVersions.joinToString(", ")}")
    println("Kafka versions: ${kafkaCpVersions.keys.joinToString(", ")}")
    println("Confluent Platform versions: ${kafkaCpVersions.values.joinToString(", ")}")
    println("Available tasks:")
    matrixTestTasks.forEach { task ->
      val icebergConnectorVersion = task.get().inputs.properties["icebergConnectorVersion"]
      val kafkaVersion = task.get().inputs.properties["kafkaVersion"]
      val cpVersion = task.get().inputs.properties["cpVersion"]
      println(
        "  - ${task.name} uses: Iceberg Connector $icebergConnectorVersion, Kafka $kafkaVersion and Confluent Platform $cpVersion"
      )
    }
  }
}

private fun suiteName(icebergVersion: String, kafkaVersion: String, cpVersion: String) =
  "intTest_iceberg_${icebergVersion.replace(".", "_")}_kafka_${kafkaVersion.replace(".", "_")}_confluent_${cpVersion.replace(".", "_")}"

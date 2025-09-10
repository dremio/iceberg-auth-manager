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

description = "Flink tests for Dremio AuthManager for Apache Iceberg"

// Matrix testing configuration
val icebergVersions = project.findProperty("authmgr.test.iceberg.versions").toString().split(",")
val flinkVersions = project.findProperty("authmgr.test.flink.versions").toString().split(",")

// Use the last combination as default for regular intTest
val defaultIcebergVersion = icebergVersions.last()
val defaultFlinkVersion = flinkVersions.last()
val defaultFlinkVersionMajorMinor = defaultFlinkVersion.substringBeforeLast(".")

val intTestBase =
  configurations.create("intTestBase") {
    description = "Base configuration holding common dependencies for Flink integration tests"
    isCanBeResolved = false
    isCanBeConsumed = false
  }

// Make intTestImplementation extend from intTestBase
configurations.intTestImplementation.get().extendsFrom(intTestBase)

dependencies {

  // Note: iceberg-core will be provided by the iceberg-flink-runtime jar,
  // with shaded dependencies; it should not leak into this project unshaded.

  // Use the shaded JAR for compilation to match runtime behavior
  intTestBase(project(":authmgr-oauth2-runtime", "shadowRuntimeElements"))

  intTestBase(testFixtures(project(":authmgr-oauth2-core")) as ModuleDependency) {
    exclude(group = "org.apache.iceberg")
  }

  intTestBase(libs.hadoop.common)
  intTestBase(libs.hadoop.hdfs.client)
  intTestBase(libs.hadoop.mapreduce.client.core)

  intTestBase(platform(libs.testcontainers.bom))
  intTestBase("org.testcontainers:testcontainers")
  intTestBase(libs.s3mock.testcontainers)

  intTestBase(platform(libs.junit.bom))
  intTestBase("org.junit.jupiter:junit-jupiter")
  intTestBase("org.junit.jupiter:junit-jupiter-api")
  intTestBase("org.junit.platform:junit-platform-launcher")

  intTestBase(libs.assertj.core)
  intTestBase(libs.mockito.core)
  intTestBase(libs.logback.classic)

  // Add to intTestImplementation all Iceberg/Flink dependencies (with default versions)
  // that are required for compilation of test classes
  intTestImplementation(
    "org.apache.iceberg:iceberg-flink-runtime-$defaultFlinkVersionMajorMinor:$defaultIcebergVersion"
  )
  intTestImplementation("org.apache.flink:flink-table-api-java:$defaultFlinkVersion")
}

// Create matrix test tasks for each version combination
val matrixTestTasks = mutableListOf<TaskProvider<Test>>()

icebergVersions.forEach { icebergVersion ->
  flinkVersions.forEach flinkVersion@{ flinkVersion ->
    if (flinkVersion.startsWith("2.") && icebergVersion.startsWith("1.9.")) {
      return@flinkVersion
    }

    val suiteName = suiteName(icebergVersion, flinkVersion)

    val runtimeConfig =
      configurations.create(suiteName) {
        extendsFrom(intTestBase)
        isCanBeResolved = true
        isCanBeConsumed = false
      }

    val flinkVersionMajorMinor = flinkVersion.substringBeforeLast(".")

    // Add version-specific dependencies
    dependencies {
      runtimeConfig(platform("org.apache.iceberg:iceberg-bom:$icebergVersion"))
      runtimeConfig(
        "org.apache.iceberg:iceberg-flink-runtime-$flinkVersionMajorMinor:$icebergVersion"
      )
      runtimeConfig("org.apache.flink:flink-table-api-java:$flinkVersion")
      runtimeConfig("org.apache.flink:flink-table-runtime:$flinkVersion")
      runtimeConfig("org.apache.flink:flink-table-planner-loader:$flinkVersion")
      runtimeConfig("org.apache.flink:flink-clients:$flinkVersion")
      runtimeConfig("org.apache.flink:flink-connector-base:$flinkVersion")
      runtimeConfig("org.apache.flink:flink-connector-files:$flinkVersion")
      runtimeConfig("org.apache.iceberg:iceberg-aws-bundle:$icebergVersion")
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
                "Runs Flink integration tests with Iceberg $icebergVersion and Flink $flinkVersion"

              // Use shared test classes from src/intTest
              testClassesDirs = sourceSets.intTest.get().output.classesDirs
              classpath = runtimeConfig + sourceSets.intTest.get().output

              dependsOn(":authmgr-oauth2-runtime:shadowJar")

              environment("AWS_REGION", "us-west-2")
              environment("AWS_ACCESS_KEY_ID", "fake")
              environment("AWS_SECRET_ACCESS_KEY", "fake")

              jvmArgs(
                "--add-exports",
                "java.base/sun.nio.ch=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.util=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.lang=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.lang.reflect=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.io=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.net=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.nio=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.util.concurrent=ALL-UNNAMED",
                "--add-opens",
                "java.base/java.security=ALL-UNNAMED",
              )

              // Set system properties to identify the versions being tested
              systemProperty("authmgr.test.iceberg.version", icebergVersion)
              systemProperty("authmgr.test.flink.version", flinkVersion)

              inputs.property("icebergVersion", icebergVersion)
              inputs.property("flinkVersion", flinkVersion)
            }
            matrixTestTasks.add(testTask)
          }
        }
      }
    }
  }
}

tasks.named<Test>("intTest").configure {
  dependsOn(tasks.named(suiteName(defaultIcebergVersion, defaultFlinkVersion)))
  // the task itself should not run any tests
  enabled = false
  description =
    "Runs Flink integration tests with the default Iceberg version ($defaultIcebergVersion) and default Flink version ($defaultFlinkVersion)."
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
    println("Flink Integration Test Matrix:")
    println("Iceberg versions: ${icebergVersions.joinToString(", ")}")
    println("Flink versions: ${flinkVersions.joinToString(", ")}")
    println("Available tasks:")
    matrixTestTasks.forEach { task ->
      val icebergVersion = task.get().inputs.properties["icebergVersion"]
      val flinkVersion = task.get().inputs.properties["flinkVersion"]
      println("  - ${task.name} uses: Iceberg $icebergVersion, Flink $flinkVersion")
    }
  }
}

private fun suiteName(icebergVersion: String, flinkVersion: String) =
  "intTest_iceberg_${icebergVersion.replace(".", "_")}_flink_${flinkVersion.replace(".", "_")}"

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

// Matrix testing configuration
val icebergVersions = project.findProperty("authmgr.test.iceberg.versions").toString().split(",")
val sparkVersions = project.findProperty("authmgr.test.spark.versions").toString().split(",")

// Use the first combination as default for regular intTest
val defaultIcebergVersion = icebergVersions.last()
val defaultSparkVersion = sparkVersions.last()

val intTestBase =
  configurations.create("intTestBase") {
    description = "Base configuration holding common dependencies for Spark integration tests"
    isCanBeResolved = false
    isCanBeConsumed = false
  }

dependencies {

  // Note: iceberg-core will be provided by the iceberg-spark-runtime jar,
  // with shaded dependencies; it should not leak into this project unshaded.

  intTestBase(project(":authmgr-oauth2-runtime"))

  intTestBase(testFixtures(project(":authmgr-oauth2-core")) as ModuleDependency) {
    exclude(group = "org.apache.iceberg")
  }

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

  // Make intTestImplementation extend from intTestBase
  configurations.intTestImplementation.get().extendsFrom(intTestBase)

  // Add to intTestImplementation all Iceberg/Spark dependencies (with default versions)
  // that are required for compilation of test classes
  intTestImplementation(platform(libs.iceberg.bom))
  intTestImplementation("org.apache.iceberg:iceberg-spark-runtime-3.5_2.12")
  intTestImplementation("org.apache.iceberg:iceberg-spark-extensions-3.5_2.12")
  intTestImplementation("org.apache.spark:spark-sql_2.12:$defaultSparkVersion")
}

// Create matrix test tasks for each version combination
val matrixTestTasks = mutableListOf<TaskProvider<Test>>()

icebergVersions.forEach { icebergVersion ->
  sparkVersions.forEach { sparkVersion ->
    val taskName =
      "intTest_iceberg${icebergVersion.replace(".", "")}_spark${sparkVersion.replace(".", "")}"

    val runtimeConfig =
      configurations.create(taskName) {
        extendsFrom(intTestBase)
        isCanBeResolved = true
        isCanBeConsumed = false
      }

    // Add version-specific dependencies
    dependencies {
      runtimeConfig(platform("org.apache.iceberg:iceberg-bom:$icebergVersion"))
      runtimeConfig("org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:$icebergVersion")
      runtimeConfig("org.apache.iceberg:iceberg-spark-extensions-3.5_2.12:$icebergVersion")
      runtimeConfig("org.apache.iceberg:iceberg-aws-bundle:$icebergVersion")
      runtimeConfig("org.apache.spark:spark-sql_2.12:$sparkVersion") {
        exclude(group = "org.apache.logging.log4j")
      }
    }

    // Create test task for this version combination
    val testTask =
      tasks.register<Test>(taskName) {
        if (System.getenv("CI") == null) {
          maxParallelForks = 2
        }

        group = "verification"
        description =
          "Runs Spark integration tests with Iceberg $icebergVersion and Spark $sparkVersion."

        // Configure the test sources and classpath
        testClassesDirs = sourceSets.intTest.get().output.classesDirs
        classpath = runtimeConfig + sourceSets.intTest.get().output

        // Enable JUnit Platform for test discovery
        useJUnitPlatform()

        dependsOn(":authmgr-oauth2-runtime:shadowJar")

        environment("AWS_REGION", "us-west-2")
        environment("AWS_ACCESS_KEY_ID", "fake")
        environment("AWS_SECRET_ACCESS_KEY", "fake")

        jvmArgs("--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED")

        // Set system properties to identify the versions being tested
        systemProperty("authmgr.test.iceberg.version", icebergVersion)
        systemProperty("authmgr.test.spark.version", sparkVersion)

        // Use unique working directory and reports
        workingDir = layout.buildDirectory.dir("tmp/$taskName").get().asFile

        // Use test name suffix to distinguish between matrix runs
        reports {
          junitXml.required.set(true)
          junitXml.outputLocation.set(layout.buildDirectory.dir("test-results/$taskName"))
          html.required.set(true)
          html.outputLocation.set(layout.buildDirectory.dir("reports/tests/$taskName"))
        }

        // Ensure unique inputs to avoid caching conflicts
        inputs.property("icebergVersion", icebergVersion)
        inputs.property("sparkVersion", sparkVersion)
      }

    matrixTestTasks.add(testTask)
  }
}

tasks.named<Test>("intTest").configure {
  dependsOn(
    tasks.named(
      "intTest_iceberg${defaultIcebergVersion.replace(".", "")}_spark${defaultSparkVersion.replace(".", "")}"
    )
  )
  // the task itself should not run any tests
  enabled = false
  description =
    "Runs Spark integration tests with the default Iceberg version ($defaultIcebergVersion) and default Spark version ($defaultSparkVersion)."
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
    println("Spark Integration Test Matrix:")
    println("Iceberg versions: ${icebergVersions.joinToString(", ")}")
    println("Spark versions: ${sparkVersions.joinToString(", ")}")
    println("Available tasks:")
    matrixTestTasks.forEach { task ->
      val icebergVersion = task.get().inputs.properties["icebergVersion"]
      val sparkVersion = task.get().inputs.properties["sparkVersion"]
      println("  - ${task.name} uses: Iceberg $icebergVersion, Spark $sparkVersion")
    }
  }
}

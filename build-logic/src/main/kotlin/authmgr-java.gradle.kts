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

import java.util.Properties
import net.ltgt.gradle.errorprone.CheckSeverity
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.named

plugins {
  jacoco
  `java-library`
  `java-test-fixtures`
  `jvm-test-suite`
  id("com.diffplug.spotless")
  id("jacoco-report-aggregation")
  id("net.ltgt.errorprone")
}

tasks.withType(JavaCompile::class.java).configureEach {
  options.release = 11
  options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Xlint:deprecation"))
  options.errorprone.disableAllWarnings = true
  options.errorprone.excludedPaths =
    ".*/${project.layout.buildDirectory.get().asFile.relativeTo(projectDir)}/generated/.*"
  val errorproneRules = rootProject.projectDir.resolve("codestyle/errorprone-rules.properties")
  inputs.file(errorproneRules).withPathSensitivity(PathSensitivity.RELATIVE)
  options.errorprone.checks.putAll(provider { memoizedErrorproneRules(errorproneRules) })
}

private fun memoizedErrorproneRules(rulesFile: File): Map<String, CheckSeverity> =
  rulesFile.reader().use {
    val rules = Properties()
    rules.load(it)
    rules
      .mapKeys { e -> (e.key as String).trim() }
      .mapValues { e -> (e.value as String).trim() }
      .filter { e -> e.key.isNotEmpty() && e.value.isNotEmpty() }
      .mapValues { e -> CheckSeverity.valueOf(e.value) }
      .toMap()
  }

tasks.register("compileAll").configure {
  group = "build"
  description = "Runs all compilation and jar tasks"
  dependsOn(tasks.withType<AbstractCompile>(), tasks.withType<ProcessResources>())
}

tasks.register("format").configure {
  group = "verification"
  description = "Runs all code formatting tasks"
  dependsOn("spotlessApply")
}

tasks.named<Test>("test").configure { jvmArgs("-Duser.language=en") }

testing {
  suites {
    withType<JvmTestSuite> {
      val libs = versionCatalogs.named("libs")

      useJUnitJupiter(
        libs
          .findLibrary("junit-bom")
          .orElseThrow { GradleException("junit-bom not declared in libs.versions.toml") }
          .map { it.version!! }
      )

      dependencies {
        implementation(project())
        implementation(testFixtures(project()))
        runtimeOnly(
          libs.findLibrary("logback-classic").orElseThrow {
            GradleException("logback-classic not declared in libs.versions.toml")
          }
        )
        implementation(
          libs.findLibrary("assertj-core").orElseThrow {
            GradleException("assertj-core not declared in libs.versions.toml")
          }
        )
        implementation(
          libs.findLibrary("mockito-core").orElseThrow {
            GradleException("mockito-core not declared in libs.versions.toml")
          }
        )
      }
    }

    register<JvmTestSuite>("intTest") {
      targets.all {
        testTask.configure { shouldRunAfter("test") }
        tasks.named("check").configure { dependsOn(testTask) }
      }
    }
  }
}

// Special handling for test-suites with type `manual-test`, which are intended to be run on demand
// rather than implicitly via `check`.
afterEvaluate {
  testing {
    suites {
      withType<JvmTestSuite> {
        // Need to do this check in an afterEvaluate, because the `withType` above gets called
        // before the configure() of a registered test suite runs.
        if (testType.get() != "manual-test") {
          targets.all {
            if (testTask.name != "test") {
              testTask.configure { shouldRunAfter("test") }
              tasks.named("check").configure { dependsOn(testTask) }
            }
          }
        }
      }
    }
  }
}

dependencies {
  val libs = versionCatalogs.named("libs")
  testFixturesImplementation(
    platform(
      libs.findLibrary("junit-bom").orElseThrow {
        GradleException("junit-bom not declared in libs.versions.toml")
      }
    )
  )
  testFixturesImplementation("org.junit.jupiter:junit-jupiter")
  testFixturesImplementation(
    libs.findLibrary("assertj-core").orElseThrow {
      GradleException("assertj-core not declared in libs.versions.toml")
    }
  )
  testFixturesImplementation(
    libs.findLibrary("mockito-core").orElseThrow {
      GradleException("mockito-core not declared in libs.versions.toml")
    }
  )
}

dependencies { errorprone(versionCatalogs.named("libs").findLibrary("errorprone").get()) }

java {
  withJavadocJar()
  withSourcesJar()
}

tasks.withType<Javadoc>().configureEach {
  val opt = options as CoreJavadocOptions
  // don't spam log w/ "warning: no @param/@return"
  opt.addStringOption("Xdoclint:-reference", "-quiet")
}

tasks.register("printRuntimeClasspath").configure {
  group = "help"
  description = "Print the classpath as a path string to be used when running tools like 'jol'"
  inputs.files(configurations.named("runtimeClasspath"))
  doLast {
    val cp = configurations.getByName("runtimeClasspath")
    val def = configurations.getByName("runtimeElements")
    logger.lifecycle("${def.outgoing.artifacts.files.asPath}:${cp.asPath}")
  }
}

configurations.all {
  rootProject
    .file("gradle/banned-dependencies.txt")
    .readText(Charsets.UTF_8)
    .trim()
    .lines()
    .map { it.trim() }
    .filterNot { it.isBlank() || it.startsWith("#") }
    .forEach { line ->
      val idx = line.indexOf(':')
      if (idx == -1) {
        exclude(group = line)
      } else {
        val group = line.substring(0, idx)
        val module = line.substring(idx + 1)
        exclude(group = group, module = module)
      }
    }
}

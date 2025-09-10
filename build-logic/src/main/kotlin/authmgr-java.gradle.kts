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

plugins {
  `java-library`
  id("com.diffplug.spotless")
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

// ensure jars conform to reproducible builds
// (https://docs.gradle.org/current/userguide/working_with_files.html#sec:reproducible_archives)
tasks.withType<AbstractArchiveTask>().configureEach {
  isPreserveFileTimestamps = false
  isReproducibleFileOrder = true
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

dependencies { errorprone(versionCatalogs.named("libs").findLibrary("errorprone").get()) }

java {
  withJavadocJar()
  withSourcesJar()
}

tasks.withType<Jar>().configureEach {
  manifest {
    attributes(
      "Implementation-Title" to project.name,
      "Implementation-Version" to project.version,
      "Implementation-Vendor" to "Dremio Corporation",
      "Implementation-URL" to "https://github.com/dremio/iceberg-auth-manager/",
    )
  }
}

if (project.hasProperty("release")) {

  fun git(vararg args: String): String {
    return rootProject.providers
      .exec {
        executable = "git"
        args(args.toList())
      }
      .standardOutput
      .asText
      .get()
      .trim()
  }

  fun gitInfo(): Map<String, String> {
    return if (rootProject.extra.has("gitReleaseInfo")) {
      @Suppress("UNCHECKED_CAST")
      rootProject.extra["gitReleaseInfo"] as Map<String, String>
    } else {
      val gitHead = git("rev-parse", "HEAD")
      val gitDescribe =
        try {
          git("describe", "--tags")
        } catch (_: Exception) {
          git("describe", "--always", "--dirty")
        }
      val info = mapOf("Build-Git-Head" to gitHead, "Build-Git-Describe" to gitDescribe)
      rootProject.extra["gitReleaseInfo"] = info
      info
    }
  }

  tasks.withType<Jar>().configureEach { manifest { attributes.putAll(gitInfo()) } }
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

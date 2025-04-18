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

includeBuild("build-logic") { name = "authmgr-build-logic" }

var authMangerBuild = file("auth-manager-build.properties")

if (authMangerBuild.exists()) {
  val props = loadProperties(authMangerBuild)
  val icebergDir = props.getProperty("included-build.iceberg.directory")
  if (!(icebergDir ?: "").isEmpty()) {
    includeBuild(icebergDir) { name = "iceberg" }
  }
}

if (!JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_11)) {
  throw GradleException("Build requires Java 11 or later")
}

val baseVersion = file("version.txt").readText().trim()

pluginManagement {
  repositories {
    mavenCentral() // prefer Maven Central, in case Gradle's repo has issues
    gradlePluginPortal()
  }
}

dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
  repositories {
    mavenCentral()
    mavenLocal()
    gradlePluginPortal()
    maven { url = uri("https://repository.apache.org/content/groups/public") }
  }
}

gradle.beforeProject {
  version = baseVersion
  group = "com.dremio.iceberg.authmgr"
}

fun authManagerProject(name: String, directory: File): ProjectDescriptor {
  include(name)
  val p = project(":$name")
  p.name = name
  p.projectDir = directory
  return p
}

fun loadProperties(file: File): Properties {
  val props = Properties()
  file.reader().use { reader -> props.load(reader) }
  return props
}

loadProperties(file("gradle/projects.main.properties")).forEach { name, directory ->
  authManagerProject(name as String, file(directory as String))
}

rootProject.name = "authmgr"

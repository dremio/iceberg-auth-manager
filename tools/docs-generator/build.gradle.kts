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
  id("authmgr-maven")
}

description = "Documentation Generator Tool for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Docs Generator") }

dependencies { implementation("com.thoughtworks.qdox:qdox:2.2.0") }

val generateDocs by
  tasks.registering(JavaExec::class) {
    group = "documentation"
    description = "Generates configuration documentation from OAuth2Properties"
    mainClass.set("com.dremio.iceberg.authmgr.docs.DocumentationGenerator")
    classpath = project(":authmgr-docs-generator").sourceSets.main.get().runtimeClasspath
    val inputFile =
      project(":authmgr-oauth2-core")
        .file("src/main/java/com/dremio/iceberg/authmgr/oauth2/OAuth2Properties.java")
    val outputFile = rootProject.file("docs/configuration.md")
    val header = file("src/main/resources/header.md").readText()
    inputs.files(inputFile, file("src/main/resources/header.md"))
    outputs.file(outputFile)
    args(
      inputFile.absolutePath,
      "com.dremio.iceberg.authmgr.oauth2.OAuth2Properties",
      header,
      outputFile.absolutePath,
    )
    doFirst { outputFile.parentFile.mkdirs() }
  }

tasks.named("build") { dependsOn(generateDocs) }

tasks.named("publish") { dependsOn(generateDocs) }

rootProject.tasks.named("spotlessMarkdown") { dependsOn(generateDocs) }

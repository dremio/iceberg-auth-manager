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
  id("authmgr-shadow-jar")
  id("authmgr-maven")
}

description = "Runtime bundle for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Runtime") }

// Create configurations to hold the core project's source and javadoc artifacts
val coreSources by
  configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    attributes {
      attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.DOCUMENTATION))
      attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
      attribute(DocsType.DOCS_TYPE_ATTRIBUTE, objects.named(DocsType.SOURCES))
    }
  }

val coreJavadoc by
  configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    attributes {
      attribute(Category.CATEGORY_ATTRIBUTE, objects.named(Category.DOCUMENTATION))
      attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL))
      attribute(DocsType.DOCS_TYPE_ATTRIBUTE, objects.named(DocsType.JAVADOC))
    }
  }

dependencies {
  api(project(":authmgr-oauth2-core")) {
    // exclude dependencies that are already provided by Iceberg runtime jars
    exclude(group = "org.apache.iceberg")
    exclude(group = "com.fasterxml.jackson.core")
    exclude(group = "com.github.ben-manes.caffeine")
    exclude(group = "org.slf4j")
  }
  coreSources(project(":authmgr-oauth2-core", "sourcesElements"))
  coreJavadoc(project(":authmgr-oauth2-core", "javadocElements"))
}

tasks.shadowJar {
  isZip64 = true
  archiveClassifier = "" // publish the shadowed JAR instead of the original JAR
  // relocate dependencies that are specific to the AuthManager
  relocate("com.nimbusds", "com.dremio.iceberg.authmgr.shaded.com.nimbusds")
  relocate("net.minidev", "com.dremio.iceberg.authmgr.shaded.net.minidev")
  relocate("org.objectweb.asm", "com.dremio.iceberg.authmgr.shaded.org.objectweb.asm")
  // relocate to same packages as in Iceberg runtime jars
  relocate("com.fasterxml.jackson", "org.apache.iceberg.shaded.com.fasterxml.jackson")
  relocate("com.github.benmanes", "org.apache.iceberg.shaded.com.github.benmanes")
  // exclude unwanted files
  exclude("META-INF/**/module-info.class")
  exclude("META-INF/proguard/**")
  exclude("iso3166_*.properties")
  minimize()
}

// Configure the source jar to copy from the core project's source jar
tasks.named<Jar>("sourcesJar") {
  dependsOn(":authmgr-oauth2-core:sourcesJar")
  from({ coreSources.incoming.artifactView { lenient(true) }.files.map { zipTree(it) } })
}

// Configure the javadoc jar to copy from the core project's javadoc jar
tasks.named<Jar>("javadocJar") {
  dependsOn(":authmgr-oauth2-core:javadocJar")
  from({ coreJavadoc.incoming.artifactView { lenient(true) }.files.map { zipTree(it) } })
}

// Skip the javadoc generation task as we'll copy from the core project
tasks.withType<Javadoc> { enabled = false }

// We're replacing the "original jar" with the uber-jar.
tasks.named("jar") { enabled = false }

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

import com.github.jengelman.gradle.plugins.shadow.transformers.ApacheNoticeResourceTransformer
import com.github.jk1.license.filter.SpdxLicenseBundleNormalizer
import com.github.jk1.license.render.ReportRenderer
import java.time.LocalDate

plugins {
  id("authmgr-java")
  id("authmgr-shadow-jar")
  id("authmgr-maven")
  id("com.github.jk1.dependency-license-report")
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
    exclude(group = "org.apache.httpcomponents.client5")
    exclude(group = "com.fasterxml.jackson.core")
    exclude(group = "com.github.ben-manes.caffeine")
    exclude(group = "org.slf4j")
  }
  coreSources(project(":authmgr-oauth2-core", "sourcesElements"))
  coreJavadoc(project(":authmgr-oauth2-core", "javadocElements"))
}

tasks.shadowJar {
  dependsOn("checkLicense")
  archiveClassifier = "" // publish the shadowed JAR instead of the original JAR
  // relocate dependencies that are specific to the AuthManager
  relocate("com.nimbusds", "com.dremio.iceberg.authmgr.shaded.com.nimbusds")
  relocate("net.minidev", "com.dremio.iceberg.authmgr.shaded.net.minidev")
  relocate("org.objectweb.asm", "com.dremio.iceberg.authmgr.shaded.org.objectweb.asm")
  relocate("io.smallrye", "com.dremio.iceberg.authmgr.shaded.io.smallrye")
  relocate("org.eclipse.microprofile", "com.dremio.iceberg.authmgr.shaded.org.eclipse.microprofile")
  relocate("org.jboss", "com.dremio.iceberg.authmgr.shaded.org.jboss")
  // relocate to same packages as in Iceberg runtime jars
  relocate("com.fasterxml.jackson", "org.apache.iceberg.shaded.com.fasterxml.jackson")
  relocate("com.github.benmanes", "org.apache.iceberg.shaded.com.github.benmanes")
  relocate("org.apache.hc", "org.apache.iceberg.shaded.org.apache.hc")
  // exclude module-info.class files
  exclude("META-INF/**/module-info.class")
  // exclude unnecessary files from Nimbus OIDC SDK and JoSE JWT
  exclude("META-INF/maven/com.github.stephenc.jcip/**")
  exclude("META-INF/maven/com.google.code.gson/**")
  exclude("META-INF/proguard/**")
  exclude("iso3166_*.properties")
  // include binary distribution LICENSE file, excluding other LICENSE files
  exclude("META-INF/LICENSE", "META-INF/LICENSE.txt")
  from("$projectDir/build/reports/license/LICENSE") { into("META-INF") }
  // include project's NOTICE then merge all NOTICE files
  from("${rootDir}/NOTICE") { into("META-INF") }
  val noticeResourceTransformer = ApacheNoticeResourceTransformer()
  noticeResourceTransformer.projectName = "Dremio AuthManager for Apache Iceberg"
  noticeResourceTransformer.copyright = "Copyright (c) ${LocalDate.now().year} Dremio"
  noticeResourceTransformer.inceptionYear = "2025"
  transform(noticeResourceTransformer)
  // exclude smallrye-config from minimizing since it has generated code
  minimize { exclude(dependency("io.smallrye.config:smallrye-config")) }
}

// Configure the source jar to copy from the core project's source jar
tasks.named<Jar>("sourcesJar") {
  dependsOn(":authmgr-oauth2-core:sourcesJar")
  duplicatesStrategy = DuplicatesStrategy.INCLUDE // LICENSE files may be duplicated
  from({ coreSources.incoming.artifactView { lenient(true) }.files.map { zipTree(it) } })
}

// Configure the javadoc jar to copy from the core project's javadoc jar
tasks.named<Jar>("javadocJar") {
  dependsOn(":authmgr-oauth2-core:javadocJar")
  duplicatesStrategy = DuplicatesStrategy.INCLUDE // LICENSE files may be duplicated
  from({ coreJavadoc.incoming.artifactView { lenient(true) }.files.map { zipTree(it) } })
}

// Skip the javadoc generation task as we'll copy from the core project
tasks.withType<Javadoc> { enabled = false }

// We're replacing the "original jar" with the uber-jar.
tasks.named("jar") { enabled = false }

licenseReport {
  outputDir = "$projectDir/build/reports/license"
  configurations = arrayOf("runtimeClasspath")
  filters = arrayOf(SpdxLicenseBundleNormalizer())
  allowedLicensesFile =
    rootProject.projectDir.resolve("gradle/license/allowed-licenses.json5").absoluteFile
  renderers = arrayOf<ReportRenderer>(BinaryDistributionLicenseGenerator())
  excludeOwnGroup = true
}

tasks.named("checkLicense") {
  inputs
    .files(rootProject.projectDir.resolve("gradle/license/allowed-licenses.json5"))
    .withPathSensitivity(PathSensitivity.RELATIVE)
}

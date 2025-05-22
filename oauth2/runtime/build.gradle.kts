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
  id("authmgr-shadow-jar")
}

dependencies {
  implementation(project(":authmgr-oauth2-core"))
}

// all dependencies are expected to be provided by Iceberg runtime jars, except the ones
// that are explicitly declared in the dependencies block above
configurations.all {
  isTransitive = false
}

tasks.shadowJar {
  archiveClassifier = "" // publish the shadowed JAR instead of the original JAR
  // relocate to same package as in Iceberg runtime jars
  relocate("com.fasterxml.jackson", "org.apache.iceberg.shaded.com.fasterxml.jackson")
  relocate("com.github.benmanes", "org.apache.iceberg.shaded.com.github.benmanes")
}

// configure the javadoc task to use the source and classpath of project ":authmgr-oauth2-core"
tasks.withType<Javadoc> {
  source = project(":authmgr-oauth2-core").tasks.named<Javadoc>("javadoc").get().source
  classpath = project(":authmgr-oauth2-core").tasks.named<Javadoc>("javadoc").get().classpath
}

// configure the source jar to contain the sources of project ":authmgr-oauth2-core"
tasks.named<Jar>("sourcesJar") {
  from(project(":authmgr-oauth2-core").sourceSets["main"].allSource)
}

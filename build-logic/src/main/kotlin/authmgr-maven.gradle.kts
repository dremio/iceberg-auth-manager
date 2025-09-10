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
  `maven-publish`
  id("base")
}

publishing {
  repositories {
    maven {
      name = "localStaging"
      url = layout.buildDirectory.dir("staging-deploy").get().asFile.toURI()
    }
  }
}

tasks.withType<Jar>().configureEach {
  from(tasks.named("generatePomFileForMavenPublication")) {
    include("pom-default.xml")
    eachFile { this.path = "META-INF/maven/${project.group}/${project.name}/pom.xml" }
  }
}

// Use afterEvaluate to ensure properties are accessed after they've been set
afterEvaluate {

  // Projects to exclude from publication and BOM
  val excludedProjects =
    setOf("authmgr-oauth2-runtime-flink-tests", "authmgr-oauth2-runtime-spark-tests")

  publishing {
    publications {
      create<MavenPublication>("maven") {
        if (project.plugins.hasPlugin("com.gradleup.shadow")) {
          from(components["shadow"])
          // Shadow component doesn't include javadoc and sources jars by default, so add them
          // explicitly
          artifact(tasks.named("javadocJar"))
          artifact(tasks.named("sourcesJar"))
        } else if (project.plugins.hasPlugin("java-platform")) {
          from(components["javaPlatform"])
        } else {
          from(components.firstOrNull { it.name == "java" })
        }

        // Suppress test fixtures capability warnings
        suppressPomMetadataWarningsFor("testFixturesApiElements")
        suppressPomMetadataWarningsFor("testFixturesRuntimeElements")

        pom {
          // Use the mavenName property if it exists, otherwise use a default
          name =
            if (project.hasProperty("mavenName")) {
              project.property("mavenName").toString()
            } else {
              "Auth Manager for Apache Iceberg - ${project.name}"
            }

          description = project.description

          url.set("https://github.com/dremio/iceberg-auth-manager")
          inceptionYear = "2025"

          licenses {
            license {
              name = "Apache-2.0"
              url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
          }

          developers {
            developer {
              id = "dremio"
              name = "Dremio"
              email = "oss@dremio.com"
              organization = "Dremio Corporation"
              organizationUrl = "https://www.dremio.com"
            }
          }

          scm {
            connection = "scm:git:git://github.com/dremio/iceberg-auth-manager.git"
            developerConnection = "scm:git:git://github.com/dremio/iceberg-auth-manager.git"
            url = "https://github.com/dremio/iceberg-auth-manager"
            if (!version.endsWith("-SNAPSHOT")) {
              tag = "authmgr-$version"
            }
          }

          if (project == rootProject) {
            withXml {
              val modules = asNode().appendNode("modules")
              rootProject.subprojects
                .filter { it.name !in excludedProjects }
                .forEach { modules.appendNode("module", it.name) }
            }
          } else {
            withXml {
              val parentNode = asNode().appendNode("parent")
              parentNode.appendNode("groupId", rootProject.group)
              parentNode.appendNode("artifactId", rootProject.name)
              parentNode.appendNode("version", rootProject.version)
            }
          }
        }
      }
    }
  }
}

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
  publications {
    // This publication is used by JReleaser
    create<MavenPublication>("staging-maven") {
      if (project.plugins.hasPlugin("com.gradleup.shadow")) {
        from(components["shadow"])
      } else {
        from(components.firstOrNull { it.name == "java" })
      }

      // Suppress test fixtures capability warnings
      suppressPomMetadataWarningsFor("testFixturesApiElements")
      suppressPomMetadataWarningsFor("testFixturesRuntimeElements")
    }
  }
  repositories {
    maven {
      name = "localStaging"
      url = layout.buildDirectory.dir("staging-deploy").get().asFile.toURI()
    }
  }
}

// Use afterEvaluate to ensure properties are accessed after they've been set
afterEvaluate {
  publishing {
    publications {
      named<MavenPublication>("staging-maven") {
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

          if (project == project.rootProject) {
            withXml {
              val modules = asNode().appendNode("modules")
              subprojects.forEach { subproject -> modules.appendNode("module", subproject.name) }
            }
          } else {
            withXml {
              val parentNode = asNode().appendNode("parent")
              parentNode.appendNode("groupId", project.rootProject.group)
              parentNode.appendNode("artifactId", project.rootProject.name)
              parentNode.appendNode("version", project.rootProject.version)
            }
            if (project.name == "authmgr-bom") {
              pom.withXml {
                val dependencies =
                  asNode().appendNode("dependencyManagement").appendNode("dependencies")

                // Add all project modules to the BOM
                rootProject.subprojects.forEach { subproject ->
                  // Skip the BOM itself
                  if (subproject.name != project.name) {
                    dependencies.appendNode("dependency").apply {
                      appendNode("groupId", subproject.group)
                      appendNode("artifactId", subproject.name)
                      appendNode("version", subproject.version)
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

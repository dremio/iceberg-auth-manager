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

plugins { `maven-publish` }

publishing {
  publications {

    // This publication is used by JReleaser
    create<MavenPublication>("staging-maven") {
      if (project.plugins.hasPlugin("com.gradleup.shadow")) {
        from(components["shadow"])
      } else {
        from(components["java"])
      }

      pom {
        name = "Auth Manager for Apache Iceberg"
        description =
          "Dremio AuthManager for Apache Iceberg is an OAuth2 manager for Apache Iceberg REST. It is a general-purpose implementation that is compatible with any Apache Iceberg REST catalog."
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
          val version = rootProject.file("version.txt").readText().trim()
          if (!version.endsWith("-SNAPSHOT")) {
            tag = "authmgr-$version"
          }
        }
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

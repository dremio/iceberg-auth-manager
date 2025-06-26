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

import org.jetbrains.gradle.ext.copyright
import org.jetbrains.gradle.ext.encodings
import org.jetbrains.gradle.ext.settings

plugins {
  id("com.diffplug.spotless")
  id("org.jetbrains.gradle.plugin.idea-ext")
}

spotless {
  java {
    target("**/*.java")
    googleJavaFormat()
    licenseHeaderFile(rootProject.file("codestyle/copyright-header-java.txt"))
    endWithNewline()
  }
  kotlinGradle {
    ktfmt().googleStyle()
    licenseHeaderFile(rootProject.file("codestyle/copyright-header-java.txt"), "$")
    target("**/*.gradle.kts")
    targetExclude("**/build/**")
  }
  format("markdown") {
    target("**/*.md")
    licenseHeaderFile(rootProject.file("codestyle/copyright-header-md.txt"), "#")
  }
  yaml {
    target("**/*.yml", "**/*.yaml")
    // delimiter can be:
    // - a comment sign not followed by another comment sign (reserved for the license header)
    // - a YAML document separator
    // - the beginning of a YAML document (key-value pair)
    licenseHeaderFile(
      rootProject.file("codestyle/copyright-header-yaml.txt"),
      " *(#(?!#)|---|[^:#\\s\\{/]+\\s*:)",
    )
  }
}

if (System.getProperty("idea.sync.active").toBoolean()) {
  idea {
    module {
      isDownloadJavadoc = false // was 'true', but didn't work
      isDownloadSources = false // was 'true', but didn't work
      inheritOutputDirs = true

      excludeDirs =
        excludeDirs +
          setOf(projectDir.resolve("build-logic/.kotlin"), projectDir.resolve(".idea")) +
          allprojects.map { prj -> prj.layout.buildDirectory.asFile.get() }
    }

    project.settings {
      copyright {
        useDefault = "ApacheLicense-v2"
        profiles.create("ApacheLicense-v2") {
          // strip trailing LF
          val copyrightText = rootProject.file("codestyle/copyright-header.txt").readText()
          notice = copyrightText
        }
      }

      encodings.encoding = "UTF-8"
      encodings.properties.encoding = "UTF-8"
    }
  }
}

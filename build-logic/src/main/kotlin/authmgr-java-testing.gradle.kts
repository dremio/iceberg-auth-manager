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

import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.named

plugins {
  jacoco
  `java-test-fixtures`
  `jvm-test-suite`
  id("jacoco-report-aggregation")
}

tasks.named<Test>("test").configure { jvmArgs("-Duser.language=en") }

testing {
  suites {
    withType<JvmTestSuite> {
      val libs = versionCatalogs.named("libs")

      useJUnitJupiter(
        libs
          .findLibrary("junit-bom")
          .orElseThrow { GradleException("junit-bom not declared in libs.versions.toml") }
          .map { it.version!! }
      )

      dependencies {
        implementation(project())
        implementation(testFixtures(project()))
        runtimeOnly(
          libs.findLibrary("logback-classic").orElseThrow {
            GradleException("logback-classic not declared in libs.versions.toml")
          }
        )
        implementation(
          libs.findLibrary("assertj-core").orElseThrow {
            GradleException("assertj-core not declared in libs.versions.toml")
          }
        )
        implementation(
          libs.findLibrary("mockito-core").orElseThrow {
            GradleException("mockito-core not declared in libs.versions.toml")
          }
        )
      }
    }

    register<JvmTestSuite>("intTest") {
      targets.all {
        testTask.configure { shouldRunAfter("test") }
        tasks.named("check").configure { dependsOn(testTask) }
      }
    }
  }
}

dependencies {
  val libs = versionCatalogs.named("libs")
  testFixturesImplementation(
    platform(
      libs.findLibrary("junit-bom").orElseThrow {
        GradleException("junit-bom not declared in libs.versions.toml")
      }
    )
  )
  testFixturesImplementation("org.junit.jupiter:junit-jupiter")
  testFixturesImplementation(
    libs.findLibrary("assertj-core").orElseThrow {
      GradleException("assertj-core not declared in libs.versions.toml")
    }
  )
  testFixturesImplementation(
    libs.findLibrary("mockito-core").orElseThrow {
      GradleException("mockito-core not declared in libs.versions.toml")
    }
  )
}

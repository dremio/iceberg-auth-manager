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

import java.time.LocalDate
import org.jreleaser.model.Active
import org.jreleaser.model.api.common.Apply
import org.jreleaser.model.api.deploy.maven.MavenCentralMavenDeployer

plugins { id("org.jreleaser") }

jreleaser {
  gitRootSearch.set(true)

  // Projects to exclude from publication and release
  val excludedProjects =
    setOf(
      "authmgr-docs-generator",
      "authmgr-oauth2-runtime-flink-tests",
      "authmgr-oauth2-runtime-spark-tests",
    )

  project {
    name.set("Dremio Iceberg AuthManager")
    description.set("Dremio AuthManager for Apache Iceberg")
    authors.set(listOf("Dremio"))
    license.set("Apache-2.0")
    links {
      homepage.set("https://github.com/dremio/iceberg-auth-manager")
      bugTracker = "https://github.com/dremio/iceberg-auth-manager/issues"
    }
    inceptionYear = "2025"
    vendor = "Dremio"
    copyright = "Copyright (c) ${LocalDate.now().year} Dremio"
  }

  files {
    subprojects.forEach { project ->
      if (project.name !in excludedProjects) {
        glob {
          pattern.set(
            project.layout.buildDirectory.dir("libs").get().asFile.absolutePath + "/**.jar"
          )
        }
      }
    }
  }

  signing {
    active.set(Active.ALWAYS)
    verify.set(false) // requires the GPG public key to be set up
    armored.set(true)
  }

  hooks {
    condition.set("'{{ Env.CI }}' == true")
    script {
      before {
        filter { includes.set(listOf("session")) }
        run.set(
          """
        echo "### {{command}}" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "| Step | Outcome |" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "| ---- | ------- |" >> ${'$'}GITHUB_STEP_SUMMARY
        """
            .trimIndent()
        )
      }
      success {
        filter { excludes.set(listOf("session")) }
        run.set(
          """
        echo "| {{event.name}} | :white_check_mark: |" >> ${'$'}GITHUB_STEP_SUMMARY
        """
            .trimIndent()
        )
      }
      success {
        filter { includes.set(listOf("session")) }
        run.set(
          """
        echo "" >> ${'$'}GITHUB_STEP_SUMMARY
        """
            .trimIndent()
        )
      }
      failure {
        filter { excludes.set(listOf("session")) }
        run.set(
          """
        echo "| {{event.name}} | :x: |" >> ${'$'}GITHUB_STEP_SUMMARY
        """
            .trimIndent()
        )
      }
      failure {
        filter { includes.set(listOf("session")) }
        run.set(
          """
        echo "" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "### Failure" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "\`\`\`" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "{{event.stacktrace}}\`\`\`" >> ${'$'}GITHUB_STEP_SUMMARY
        echo "" >> ${'$'}GITHUB_STEP_SUMMARY
        """
            .trimIndent()
        )
      }
    }
  }

  release {
    github {
      releaseName.set("{{projectNameCapitalized}} {{projectVersionNumber}}")
      repoOwner.set("dremio")
      name.set("iceberg-auth-manager")
      branch.set("main")
      tagName.set("authmgr-{{projectVersion}}")
      commitAuthor {
        name.set("{{projectNameCapitalized}} Release Workflow [bot]")
        email.set("authmgr-release-workflow-noreply@dremio.com")
      }
      milestone {
        close.set(true)
        name.set("{{projectVersionNumber}}")
      }
      issues {
        // TODO enable when the CI user has permissions to close issues
        enabled.set(false)
        comment.set(
          "🎉 This issue has been resolved in version {{projectVersionNumber}} ([Release Notes]({{releaseNotesUrl}}))"
        )
        applyMilestone.set(Apply.ALWAYS)
      }
      // TODO enable when the CI user has permissions to write to discussions
      discussionCategoryName.set("")
      changelog {
        links.set(true)
        skipMergeCommits.set(true)
        formatted.set(Active.ALWAYS)
        preset.set("conventional-commits")
        categoryTitleFormat.set("### {{categoryTitle}}")
        content.set(
          """
          ## Try It Out
          {{projectNameCapitalized}} is available as a Maven artifact from [Maven Central](https://central.sonatype.com/namespace/com.dremio.iceberg.authmgr).
          You can also download the latest version from the [GitHub Releases page]({{repoUrl}}/releases).
          ## Highlights
          The full changelog can be found [here]({{repoUrl}}/compare/{{previousTagName}}...{{tagName}}).
          {{changelogChanges}}
          {{changelogContributors}}
          """
            .trimIndent()
        )
        contributors {
          format.set(
            "- {{contributorName}}{{#contributorUsernameAsLink}} ({{.}}){{/contributorUsernameAsLink}}"
          )
        }
        hide {
          categories.set(listOf("test", "tasks", "build", "docs"))
          contributors.set(listOf("[bot]", "renovate-bot", "GitHub"))
        }
      }
    }
  }

  deploy {
    maven {
      mavenCentral {
        create("sonatype") {
          stage.set(MavenCentralMavenDeployer.Stage.FULL)
          active.set(Active.RELEASE_PRERELEASE)
          url.set("https://central.sonatype.com/api/v1/publisher")
          applyMavenCentralRules.set(true)
          // Parent POM
          stagingRepository(
            rootProject.layout.buildDirectory.dir("staging-deploy").get().asFile.absolutePath
          )
          // Child POMs
          subprojects.forEach { project ->
            if (project.name !in excludedProjects) {
              stagingRepository(
                project.layout.buildDirectory.dir("staging-deploy").get().asFile.absolutePath
              )
            }
          }
        }
      }
    }
  }
}

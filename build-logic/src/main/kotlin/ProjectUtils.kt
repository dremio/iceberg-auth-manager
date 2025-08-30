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

import org.gradle.api.Project
import org.gradle.api.internal.artifacts.dependencies.DefaultProjectDependencyConstraint

/**
 * Returns the set of projects that should be published to Maven repositories.
 * This includes the root project (parent POM), the BOM project, and all projects
 * that are listed as constraints in the BOM's api configuration.
 */
fun Project.publishedProjects(): Set<Project> {
  val bomProject = rootProject.subprojects.first { it.name == "authmgr-bom" }
  return buildSet {
    add(rootProject) // parent POM
    add(bomProject)
    bomProject.configurations
      .findByName("api")
      ?.allDependencyConstraints
      ?.filterIsInstance<DefaultProjectDependencyConstraint>()
      ?.forEach { constraint ->
        add(
          rootProject.subprojects.first { it.name == constraint.projectDependency.name }
        )
      }
  }
}

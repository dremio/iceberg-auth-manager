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

import com.github.jk1.license.License
import com.github.jk1.license.LicenseReportExtension
import com.github.jk1.license.ModuleData
import com.github.jk1.license.ProjectData
import com.github.jk1.license.render.ReportRenderer
import org.gradle.api.GradleException
import java.io.File
import java.io.FileWriter

/**
 * Custom renderer that generates a LICENSE file for binary distributions.
 */
class BinaryDistributionLicenseGenerator() : ReportRenderer {

    override fun render(data: ProjectData?) {
        if (data == null) return

        val config = data.project.extensions.getByType(LicenseReportExtension::class.java)
        val outputDir = File(config.outputDir)
        if (!outputDir.exists()) {
            outputDir.mkdirs()
        }

        val outputFile = File(outputDir, "LICENSE")
        FileWriter(outputFile).use { writer ->

            // Write the full Apache License 2.0 text
            writer.write(data.project.rootProject.file("LICENSE").readText())

            // Write third-party dependencies section
            writer.write("\n================================================================================\n\n")
            writer.write("THIRD-PARTY DEPENDENCIES\n\n")
            writer.write("This product includes software developed by the following third parties:\n\n")

            val dependenciesByGroup = groupDependencies(data)

            dependenciesByGroup.forEach { (group, modules) ->
                writer.write("--------------------------------------------------------------------------------\n\n")

                writer.write("Group: $group\n")
                writer.write("\nArtifacts:\n")
                modules.forEach { module ->
                    writer.write("- $group:${module.name}:${module.version}\n")
                }

                val licenseInfo = getLicenseInfo(modules)

                writer.write("\nLicenses:\n")
                licenseInfo.forEach { entry ->
                    writer.write("- ${entry.key}${entry.value?.url?.let { " ($it)" }}\n")
                }

                writer.write("\n")
            }
        }
    }

    private fun groupDependencies(data: ProjectData): Map<String, List<ModuleData>> {
        return data.allDependencies.filter { it.group.isNotEmpty() && it.name.isNotEmpty() && it.hasArtifactFile }
            .groupBy { it.group }.toSortedMap()
    }

    private fun getLicenseInfo(modules: List<ModuleData>): Map<String?, License?> {
        val pomLicenses =
            modules.flatMap { it.poms }.map { it.licenses }.flatten().associateBy { it.name }
        if (pomLicenses.isEmpty()) {
            throw GradleException("Missing license information in group: ${modules.first().group}")
        }
        return pomLicenses
    }
}


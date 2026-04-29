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

plugins { `kotlin-dsl` }

dependencies {
  implementation(gradleKotlinDsl())
  implementation(baselibs.errorprone)
  implementation(baselibs.idea.ext)
  implementation(baselibs.license.report)
  implementation(baselibs.shadow)
  implementation(baselibs.spotless)
  implementation(baselibs.jreleaser)

  // JReleaser 1.23.0 still references GpgObjectSigner, removed in JGit 7.x;
  // Spotless 8.4.0 pulls JGit 7.x onto the same classpath. Force JGit to 5.13.x
  // until JReleaser upgrades (https://github.com/jreleaser/jreleaser/issues/1846).
  implementation("org.eclipse.jgit:org.eclipse.jgit") {
    version { strictly("5.13.5.202508271544-r") }
    because("JReleaser 1.23.0 references GpgObjectSigner removed in JGit 7.x")
  }
}

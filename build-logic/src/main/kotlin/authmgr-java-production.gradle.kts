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

import org.gradle.api.tasks.compile.JavaCompile

plugins { id("authmgr-java") }

tasks.withType(JavaCompile::class.java).configureEach {
  // Default to Java 11 for main sources, Java 21 for test sources
  if (name == "compileJava") {
    options.release = 11
  } else {
    options.release = 21
  }
}

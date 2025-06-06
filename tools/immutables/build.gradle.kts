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
  id("authmgr-java")
  id("authmgr-maven")
}

description = "Immutables annotations for Dremio AuthManager for Apache Iceberg"

ext { set("mavenName", "Auth Manager for Apache Iceberg - OAuth2 - Immutables") }

val processor by configurations.creating

processor.extendsFrom(configurations.api.get())

dependencies {
  api(libs.immutables.builder)
  api(libs.immutables.value.annotations)

  processor(libs.immutables.value.processor)
  processor(project)
}

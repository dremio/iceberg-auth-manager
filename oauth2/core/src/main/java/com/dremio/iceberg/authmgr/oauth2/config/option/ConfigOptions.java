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
package com.dremio.iceberg.authmgr.oauth2.config.option;

import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

public final class ConfigOptions {

  public static ConfigOption<String> simple(String option, Consumer<String> setter) {
    return ImmutableSimpleConfigOption.<String>builder()
        .option(option)
        .setter(setter)
        .converter(Function.identity())
        .build();
  }

  public static <T> ConfigOption<T> simple(
      String option, Consumer<T> setter, Function<String, T> converter) {
    return ImmutableSimpleConfigOption.<T>builder()
        .option(option)
        .setter(setter)
        .converter(converter)
        .build();
  }

  public static ConfigOption<Map<String, String>> prefixMap(
      String prefix, Consumer<Map<String, String>> setter) {
    return ImmutablePrefixMapConfigOption.builder().prefix(prefix).setter(setter).build();
  }

  public static ConfigOption<Map<String, String>> prefixMap(
      String prefix, String replacementPrefix, Consumer<Map<String, String>> setter) {
    return ImmutablePrefixMapConfigOption.builder()
        .prefix(prefix)
        .replacementPrefix(replacementPrefix)
        .setter(setter)
        .build();
  }

  private ConfigOptions() {}
}

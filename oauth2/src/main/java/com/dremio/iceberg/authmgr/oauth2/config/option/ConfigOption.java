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
import java.util.Optional;
import java.util.function.Consumer;

/**
 * This class provides a way to define a configuration option, with its setter method, a fallback
 * mechanism, and methods to parse and apply the option value from a given properties map.
 *
 * @param <T> the type of the configuration option
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public abstract class ConfigOption<T> {

  public abstract void apply(Map<String, String> properties);

  public final void merge(Map<String, String> properties, T fallback) {
    withFallback(fallback).apply(properties);
  }

  public final void merge(Map<String, String> properties, Optional<T> fallback) {
    withFallback(fallback).apply(properties);
  }

  protected abstract Consumer<T> setter();

  protected abstract Optional<T> fallback();

  protected abstract ConfigOption<T> withFallback(T value);

  protected abstract ConfigOption<T> withFallback(Optional<? extends T> value);

  protected static boolean shouldSetOption(String value) {
    return value != null && !value.isBlank();
  }
}

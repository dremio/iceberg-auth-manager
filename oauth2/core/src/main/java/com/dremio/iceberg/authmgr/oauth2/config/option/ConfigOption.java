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
 * This class provides an abstraction to work with configuration options. It exposes, for each
 * configuration option, a setter method, a fallback mechanism to retrieve a default value, and
 * methods to set the option value from a properties map.
 *
 * <p>There are two subclasses of this class:
 *
 * <ul>
 *   <li>{@link SimpleConfigOption} for simple configuration options defined by a single
 *       configuration property.
 *   <li>{@link PrefixMapConfigOption} for map-type configuration options that are defined by
 *       several configuration properties sharing a common prefix (a.k.a. "prefix maps").
 * </ul>
 *
 * @param <T> the type of the configuration option
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public abstract class ConfigOption<T> {

  /**
   * Sets the configuration option value using the provided properties map.
   *
   * <p>If the option is present in the map and is not blank, it will set the value using the
   * provided {@link #setter()}.
   *
   * <p>If the option is not present in the map, it will use the {@link #fallback()} value if
   * available.
   */
  public abstract void set(Map<String, String> properties);

  /**
   * Sets the configuration option value using the provided properties map and the provided fallback
   * value.
   *
   * <p>This is a convenience method ; it is equivalent to calling {@link #withFallback(Object)} and
   * then {@link #set(Map)}.
   */
  public final void set(Map<String, String> properties, T fallback) {
    withFallback(fallback).set(properties);
  }

  /**
   * Sets the configuration option value using the provided properties map and the provided fallback
   * value.
   *
   * <p>This is a convenience method; it is equivalent to calling {@link #withFallback(Object)} and
   * then {@link #set(Map)}.
   */
  public final void set(Map<String, String> properties, Optional<T> fallback) {
    withFallback(fallback).set(properties);
  }

  /** Returns the setter for this configuration option. */
  protected abstract Consumer<T> setter();

  /**
   * Returns the fallback value for this configuration option.
   *
   * <p>This value is used when the option is not present in the properties map or when the value is
   * blank.
   */
  protected abstract Optional<T> fallback();

  protected abstract ConfigOption<T> withFallback(T value);

  protected abstract ConfigOption<T> withFallback(Optional<? extends T> value);

  protected static boolean shouldSetOption(String value) {
    return value != null && !value.isBlank();
  }
}

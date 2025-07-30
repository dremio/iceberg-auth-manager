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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TestSimpleConfigOption {

  @Test
  void testSetWithValidValue() {
    AtomicReference<String> result = new AtomicReference<>();
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("test.option", "test-value");
    option.set(properties);
    assertThat(result.get()).isEqualTo("test-value");
  }

  @Test
  void testSetWithValueTrimming() {
    AtomicReference<String> result = new AtomicReference<>();
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("test.option", "  test-value  ");
    option.set(properties);
    assertThat(result.get()).isEqualTo("test-value");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   ", "\t", "\n"})
  void testSetWithBlankValues(String blankValue) {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("test.option", blankValue);
    option.set(properties);
    // Should not set the value when it's blank
    assertThat(result.get()).isEqualTo("initial");
  }

  @Test
  void testSetWithNullValue() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = new java.util.HashMap<>();
    properties.put("test.option", null);
    option.set(properties);
    // Should not set the value when it's null
    assertThat(result.get()).isEqualTo("initial");
  }

  @Test
  void testSetWithMissingOptionNoFallback() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("other.option", "other-value");
    option.set(properties);
    // Should not change the value when option is missing from map and no fallback
    assertThat(result.get()).isEqualTo("initial");
  }

  @Test
  void testSetWithMissingOptionWithFallback() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option =
        ConfigOptions.simple("test.option", result::set).withFallback("fallback-value");
    Map<String, String> properties = Map.of("other.option", "other-value");
    option.set(properties);
    assertThat(result.get()).isEqualTo("fallback-value");
  }

  @Test
  void testSetWithFallbackMethod() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("other.option", "other-value");
    option.set(properties, "fallback-value");
    assertThat(result.get()).isEqualTo("fallback-value");
  }

  @Test
  void testSetWithIntegerConverter() {
    AtomicReference<Integer> result = new AtomicReference<>();
    ConfigOption<Integer> option =
        ConfigOptions.simple("test.option", result::set, Integer::parseInt);
    Map<String, String> properties = Map.of("test.option", "123");
    option.set(properties);
    assertThat(result.get()).isEqualTo(123);
  }

  @Test
  void testSetWithBooleanConverter() {
    AtomicReference<Boolean> result = new AtomicReference<>();
    ConfigOption<Boolean> option =
        ConfigOptions.simple("test.option", result::set, Boolean::parseBoolean);
    Map<String, String> properties = Map.of("test.option", "true");
    option.set(properties);
    assertThat(result.get()).isEqualTo(true);
  }

  @Test
  void testSetWithDurationConverter() {
    AtomicReference<Duration> result = new AtomicReference<>();
    ConfigOption<Duration> option =
        ConfigOptions.simple("test.option", result::set, Duration::parse);
    Map<String, String> properties = Map.of("test.option", "PT30S");
    option.set(properties);
    assertThat(result.get()).isEqualTo(Duration.ofSeconds(30));
  }

  @Test
  void testSetWithStringTransformConverter() {
    AtomicReference<String> result = new AtomicReference<>();
    ConfigOption<String> option =
        ConfigOptions.simple("test.option", result::set, String::toLowerCase);
    Map<String, String> properties = Map.of("test.option", "UPPER");
    option.set(properties);
    assertThat(result.get()).isEqualTo("upper");
  }

  @Test
  void testSetWithConverterException() {
    AtomicReference<Integer> result = new AtomicReference<>();
    ConfigOption<Integer> option =
        ConfigOptions.simple("test.option", result::set, Integer::parseInt);
    Map<String, String> properties = Map.of("test.option", "not-a-number");
    assertThatThrownBy(() -> option.set(properties))
        .isInstanceOf(NumberFormatException.class)
        .hasMessageContaining("not-a-number");
  }

  @Test
  void testSetWithEmptyProperties() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    option.set(Map.of());
    assertThat(result.get()).isEqualTo("initial");
  }

  @Test
  void testSetWithNullProperties() {
    AtomicReference<String> result = new AtomicReference<>();
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    assertThatThrownBy(() -> option.set(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Invalid properties map: null");
  }

  @Test
  void testSetWithOptionalFallback() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("other.option", "other-value");
    option.set(properties, Optional.of("optional-fallback"));
    assertThat(result.get()).isEqualTo("optional-fallback");
  }

  @Test
  void testSetWithEmptyOptionalFallback() {
    AtomicReference<String> result = new AtomicReference<>("initial");
    ConfigOption<String> option = ConfigOptions.simple("test.option", result::set);
    Map<String, String> properties = Map.of("other.option", "other-value");
    option.set(properties, Optional.empty());
    // Should not change when optional fallback is empty
    assertThat(result.get()).isEqualTo("initial");
  }
}

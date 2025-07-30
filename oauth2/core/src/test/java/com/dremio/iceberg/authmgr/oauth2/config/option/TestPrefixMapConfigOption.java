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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TestPrefixMapConfigOption {

  @Test
  void testSetWithPrefixedProperties() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties =
        Map.of(
            "oauth.client_id", "test-client",
            "oauth.client_secret", "test-secret",
            "oauth.scope", "read write",
            "other.property", "ignored");

    option.set(properties);

    Map<String, String> expected =
        Map.of(
            "client_id", "test-client",
            "client_secret", "test-secret",
            "scope", "read write");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithValueTrimming() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties =
        Map.of(
            "oauth.client_id", "  test-client  ",
            "oauth.client_secret", "\ttest-secret\n");

    option.set(properties);

    Map<String, String> expected =
        Map.of(
            "client_id", "test-client",
            "client_secret", "test-secret");
    assertThat(result.get()).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   ", "\t", "\n"})
  void testSetWithBlankValuesRemovesEntries(String blankValue) {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", result::set)
            .withFallback(Map.of("client_id", "existing-client", "scope", "existing-scope"));

    Map<String, String> properties =
        Map.of(
            "oauth.client_id",
            "new-client",
            "oauth.scope",
            blankValue // This should remove the scope entry
            );

    option.set(properties);

    // Should keep client_id with new value, but remove scope
    Map<String, String> expected = Map.of("client_id", "new-client");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithNullValueRemovesEntry() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", result::set)
            .withFallback(Map.of("client_id", "existing-client", "scope", "existing-scope"));

    Map<String, String> properties = new HashMap<>();
    properties.put("oauth.client_id", "new-client");
    properties.put("oauth.scope", null); // This should remove the scope entry

    option.set(properties);

    // Should keep client_id with new value, but remove scope
    Map<String, String> expected = Map.of("client_id", "new-client");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithReplacementPrefix() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", "auth.", result::set);

    Map<String, String> properties =
        Map.of(
            "oauth.client_id", "test-client",
            "oauth.client_secret", "test-secret");

    option.set(properties);

    Map<String, String> expected =
        Map.of(
            "auth.client_id", "test-client",
            "auth.client_secret", "test-secret");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithFallbackMerging() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    Map<String, String> fallback =
        Map.of(
            "client_id", "fallback-client",
            "timeout", "30s",
            "scope", "fallback-scope");
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", result::set).withFallback(fallback);

    Map<String, String> properties =
        Map.of(
            "oauth.client_id", "new-client",
            "oauth.client_secret", "new-secret");

    option.set(properties);

    // Should merge with fallback, overriding client_id but keeping timeout and scope
    Map<String, String> expected =
        Map.of(
            "client_id", "new-client",
            "client_secret", "new-secret",
            "timeout", "30s",
            "scope", "fallback-scope");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithEmptyUpdatesUsesFallback() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    Map<String, String> fallback = Map.of("client_id", "fallback-client");
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", result::set).withFallback(fallback);

    Map<String, String> properties = Map.of("other.property", "ignored");

    option.set(properties);

    assertThat(result.get()).isEqualTo(fallback);
  }

  @Test
  void testSetWithEmptyUpdatesNoFallback() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>(Map.of("initial", "value"));
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties = Map.of("other.property", "ignored");

    option.set(properties);

    // Should not change the value when no updates and no fallback
    assertThat(result.get()).isEqualTo(Map.of("initial", "value"));
  }

  @Test
  void testSetWithFallbackMethod() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties = Map.of("other.property", "ignored");
    Map<String, String> fallback = Map.of("client_id", "fallback-client");

    option.set(properties, fallback);

    assertThat(result.get()).isEqualTo(fallback);
  }

  @Test
  void testSetWithEmptyProperties() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>(Map.of("initial", "value"));
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    option.set(Map.of());

    // Should not change when no matching properties
    assertThat(result.get()).isEqualTo(Map.of("initial", "value"));
  }

  @Test
  void testSetWithNullProperties() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);
    assertThatThrownBy(() -> option.set(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Invalid properties map: null");
  }

  @Test
  void testSetWithReplacementPrefixAndFallback() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    Map<String, String> fallback =
        Map.of(
            "auth.timeout", "30s",
            "auth.scope", "fallback-scope");
    ConfigOption<Map<String, String>> option =
        ConfigOptions.prefixMap("oauth.", "auth.", result::set).withFallback(fallback);

    Map<String, String> properties =
        Map.of(
            "oauth.client_id", "new-client",
            "oauth.scope", "" // This should remove the scope entry
            );

    option.set(properties);

    // Should merge with fallback, add client_id with replacement prefix, keep timeout, remove scope
    Map<String, String> expected =
        Map.of(
            "auth.client_id", "new-client",
            "auth.timeout", "30s");
    assertThat(result.get()).isEqualTo(expected);
  }

  @Test
  void testSetWithEmptyPrefix() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    assertThatThrownBy(() -> ConfigOptions.prefixMap("", result::set))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Prefix cannot be empty");
  }

  @Test
  void testSetWithEmptyReplacement() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    assertThatThrownBy(() -> ConfigOptions.prefixMap("oauth.", "", result::set))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Replacement prefix cannot be empty");
  }

  @Test
  void testSetWithOptionalFallback() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>();
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties = Map.of("other.property", "ignored");
    Map<String, String> fallback = Map.of("client_id", "optional-fallback");

    option.set(properties, Optional.of(fallback));

    assertThat(result.get()).isEqualTo(fallback);
  }

  @Test
  void testSetWithEmptyOptionalFallback() {
    AtomicReference<Map<String, String>> result = new AtomicReference<>(Map.of("initial", "value"));
    ConfigOption<Map<String, String>> option = ConfigOptions.prefixMap("oauth.", result::set);

    Map<String, String> properties = Map.of("other.property", "ignored");

    option.set(properties, Optional.empty());

    // Should not change when optional fallback is empty and no updates
    assertThat(result.get()).isEqualTo(Map.of("initial", "value"));
  }
}

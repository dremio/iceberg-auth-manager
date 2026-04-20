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
package com.dremio.iceberg.authmgr.oauth2.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.Map;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ConfigRelocationInterceptorTest {

  @ParameterizedTest
  @MethodSource
  void testToCanonicalName(String property, String expected) {
    assertThat(ConfigRelocationInterceptor.toCanonicalName(property)).isEqualTo(expected);
  }

  static Stream<Arguments> testToCanonicalName() {
    return Stream.of(
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback-https",
            "rest.auth.oauth2.auth-code.callback.https"),
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback-bind-port",
            "rest.auth.oauth2.auth-code.callback.bind-port"),
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback-bind-host",
            "rest.auth.oauth2.auth-code.callback.bind-host"),
        Arguments.of("some.other.property", "some.other.property"));
  }

  @ParameterizedTest
  @MethodSource
  void testToLegacyName(String property, String expected) {
    assertThat(ConfigRelocationInterceptor.toLegacyName(property)).isEqualTo(expected);
  }

  static Stream<Arguments> testToLegacyName() {
    return Stream.of(
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback.https",
            "rest.auth.oauth2.auth-code.callback-https"),
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback.bind-port",
            "rest.auth.oauth2.auth-code.callback-bind-port"),
        Arguments.of(
            "rest.auth.oauth2.auth-code.callback.bind-host",
            "rest.auth.oauth2.auth-code.callback-bind-host"),
        Arguments.of("some.other.property", "some.other.property"));
  }

  @Test
  void testIterateNamesReturnsCanonicalNamesOnly() {
    SmallRyeConfig config =
        new SmallRyeConfigBuilder()
            .setAddDefaultSources(false)
            .setAddDiscoveredSources(false)
            .setAddDiscoveredConverters(false)
            .setAddDiscoveredInterceptors(false)
            .setAddDiscoveredSecretKeysHandlers(false)
            .setAddDiscoveredValidator(false)
            .withInterceptors(new ConfigRelocationInterceptor())
            .withSources(
                new MapBackedConfigSource(
                    "catalog-properties",
                    Map.of(
                        "rest.auth.oauth2.auth-code.callback-https", "true",
                        "rest.auth.oauth2.auth-code.callback-bind-port", "8080",
                        "rest.auth.oauth2.auth-code.callback-bind-host", "localhost"),
                    1000) {})
            .build();
    assertThat(StreamSupport.stream(config.getPropertyNames().spliterator(), false).toList())
        .containsExactlyInAnyOrder(
            "rest.auth.oauth2.auth-code.callback.https",
            "rest.auth.oauth2.auth-code.callback.bind-port",
            "rest.auth.oauth2.auth-code.callback.bind-host");
  }

  @Test
  void testCanonicalLookupsResolveLegacyAliases() {
    SmallRyeConfig config =
        new SmallRyeConfigBuilder()
            .setAddDefaultSources(false)
            .setAddDiscoveredSources(false)
            .setAddDiscoveredConverters(false)
            .setAddDiscoveredInterceptors(false)
            .setAddDiscoveredSecretKeysHandlers(false)
            .setAddDiscoveredValidator(false)
            .withInterceptors(new ConfigRelocationInterceptor())
            .withSources(
                new MapBackedConfigSource(
                    "catalog-properties",
                    Map.of(
                        "rest.auth.oauth2.auth-code.callback-https", "true",
                        "rest.auth.oauth2.auth-code.callback-bind-port", "8080",
                        "rest.auth.oauth2.auth-code.callback-bind-host", "localhost"),
                    1000) {})
            .build();
    assertThat(config.getRawValue("rest.auth.oauth2.auth-code.callback.https")).isEqualTo("true");
    assertThat(config.getRawValue("rest.auth.oauth2.auth-code.callback.bind-port"))
        .isEqualTo("8080");
    assertThat(config.getRawValue("rest.auth.oauth2.auth-code.callback.bind-host"))
        .isEqualTo("localhost");
  }
}

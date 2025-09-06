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

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.stream.Stream;
import org.apache.iceberg.util.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ConfigSanitizerTest {

  private List<Pair<String, String>> messages;
  private BiConsumer<String, String> consumer;

  @BeforeEach
  void setUp() {
    messages = new ArrayList<>();
    consumer = (msg, arg) -> messages.add(Pair.of(msg, arg));
  }

  @AfterEach
  void tearDown() {
    messages.clear();
  }

  @Test
  void contextEmptyProperties() {
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeContextProperties(Map.of());
    assertThat(actual).isEmpty();
    assertThat(messages).isEmpty();
  }

  @Test
  void contextAllowedProperties() {
    Map<String, String> input =
        Map.of(
            OAuth2Properties.Basic.CLIENT_ID,
            "client1",
            OAuth2Properties.Basic.CLIENT_SECRET,
            "secret",
            OAuth2Properties.Basic.TOKEN_ENDPOINT,
            "https://example.com/token",
            "custom.property",
            "value");
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeContextProperties(input);
    assertThat(actual).isEqualTo(input);
    assertThat(messages).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("contextDenyListProperties")
  void contextForbiddenProperties(String forbiddenProperty) {
    Map<String, String> input =
        Map.of(forbiddenProperty, "forbidden", "allowed.property", "allowed");
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeContextProperties(input);
    assertThat(actual).containsOnly(entry("allowed.property", "allowed"));
    assertThat(messages).hasSize(1);
    Pair<String, String> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Ignoring property '{}': this property is not allowed in a session context.");
    assertThat(message).extracting(Pair::second).isEqualTo(forbiddenProperty);
  }

  static Stream<String> contextDenyListProperties() {
    return Stream.of(
        OAuth2Properties.System.AGENT_NAME,
        OAuth2Properties.System.SESSION_CACHE_TIMEOUT,
        OAuth2Properties.Http.CLIENT_TYPE,
        OAuth2Properties.Http.READ_TIMEOUT,
        OAuth2Properties.Http.CONNECT_TIMEOUT,
        OAuth2Properties.Http.HEADERS_PREFIX + "custom",
        OAuth2Properties.Http.COMPRESSION_ENABLED,
        OAuth2Properties.Http.SSL_PROTOCOLS,
        OAuth2Properties.Http.SSL_CIPHER_SUITES,
        OAuth2Properties.Http.SSL_HOSTNAME_VERIFICATION_ENABLED,
        OAuth2Properties.Http.SSL_TRUST_ALL,
        OAuth2Properties.Http.SSL_TRUSTSTORE_PATH,
        OAuth2Properties.Http.SSL_TRUSTSTORE_PASSWORD,
        OAuth2Properties.Http.PROXY_HOST,
        OAuth2Properties.Http.PROXY_PORT,
        OAuth2Properties.Http.PROXY_USERNAME,
        OAuth2Properties.Http.PROXY_PASSWORD);
  }

  @Test
  void tableEmptyProperties() {
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeTableProperties(Map.of());
    assertThat(actual).isEmpty();
    assertThat(messages).isEmpty();
  }

  @Test
  void tableAllowedProperties() {
    Map<String, String> input =
        Map.of(
            OAuth2Properties.Basic.SCOPE,
            "read write",
            OAuth2Properties.Basic.TOKEN_ENDPOINT,
            "https://example.com/token",
            "custom.property",
            "value");
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeTableProperties(input);
    assertThat(actual).isEqualTo(input);
    assertThat(messages).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("tableDenyListProperties")
  void tableForbiddenProperties(String forbiddenProperty) {
    Map<String, String> input =
        Map.of(forbiddenProperty, "forbidden", "allowed.property", "allowed");
    Map<String, String> actual = new ConfigSanitizer(consumer).sanitizeTableProperties(input);
    assertThat(actual).containsOnly(entry("allowed.property", "allowed"));
    assertThat(messages).hasSize(1);
    Pair<String, String> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo(
            "Ignoring property '{}': this property is not allowed to be vended by catalog servers.");
    assertThat(message).extracting(Pair::second).isEqualTo(forbiddenProperty);
  }

  static Stream<String> tableDenyListProperties() {
    return Stream.concat(
        ConfigSanitizer.TABLE_DENY_LIST.stream(),
        Stream.of(
            OAuth2Properties.System.AGENT_NAME,
            OAuth2Properties.System.SESSION_CACHE_TIMEOUT,
            OAuth2Properties.Http.CLIENT_TYPE,
            OAuth2Properties.Http.READ_TIMEOUT,
            OAuth2Properties.Http.CONNECT_TIMEOUT,
            OAuth2Properties.Http.HEADERS_PREFIX + "custom",
            OAuth2Properties.Http.COMPRESSION_ENABLED,
            OAuth2Properties.Http.SSL_PROTOCOLS,
            OAuth2Properties.Http.SSL_CIPHER_SUITES,
            OAuth2Properties.Http.SSL_HOSTNAME_VERIFICATION_ENABLED,
            OAuth2Properties.Http.SSL_TRUST_ALL,
            OAuth2Properties.Http.SSL_TRUSTSTORE_PATH,
            OAuth2Properties.Http.SSL_TRUSTSTORE_PASSWORD,
            OAuth2Properties.Http.PROXY_HOST,
            OAuth2Properties.Http.PROXY_PORT,
            OAuth2Properties.Http.PROXY_USERNAME,
            OAuth2Properties.Http.PROXY_PASSWORD));
  }
}

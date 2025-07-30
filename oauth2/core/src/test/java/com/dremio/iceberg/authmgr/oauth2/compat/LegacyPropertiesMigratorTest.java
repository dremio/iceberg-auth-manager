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
package com.dremio.iceberg.authmgr.oauth2.compat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.InstanceOfAssertFactories.array;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.iceberg.rest.auth.OAuth2Properties;
import org.apache.iceberg.util.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class LegacyPropertiesMigratorTest {

  private List<Pair<String, String[]>> messages;
  private BiConsumer<String, String[]> consumer;

  @BeforeEach
  void setUp() {
    messages = new ArrayList<>();
    consumer = (msg, args) -> messages.add(Pair.of(msg, args));
  }

  @AfterEach
  void tearDown() {
    messages.clear();
  }

  @Test
  void emptyMap() {
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(Map.of());
    assertThat(actual).isEmpty();
    assertThat(messages).isEmpty();
  }

  @Test
  void noLegacyProperties() {
    Map<String, String> input =
        Map.of(
            Basic.CLIENT_ID,
            "client1",
            Basic.CLIENT_SECRET,
            "secret",
            "non.oauth2.property",
            "value");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    // Only OAuth2 properties should be included
    assertThat(actual)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of(
                Basic.CLIENT_ID, "client1",
                Basic.CLIENT_SECRET, "secret"));
    assertThat(messages).isEmpty();
  }

  @ParameterizedTest
  @MethodSource
  void credential(String credentialValue, Map<String, String> expected) {
    Map<String, String> input = Map.of(OAuth2Properties.CREDENTIAL, credentialValue);
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).containsExactlyInAnyOrderEntriesOf(expected);
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use options {} {} {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.CREDENTIAL, Basic.CLIENT_ID, "and", Basic.CLIENT_SECRET);
  }

  static Stream<Arguments> credential() {
    return Stream.of(
        Arguments.of(
            "client1:secret1",
            Map.of(
                Basic.CLIENT_ID, "client1",
                Basic.CLIENT_SECRET, "secret1")),
        Arguments.of("secret-only", Map.of(Basic.CLIENT_SECRET, "secret-only")));
  }

  @Test
  void credentialInvalid() {
    Map<String, String> input = Map.of(OAuth2Properties.CREDENTIAL, "client:secret:extra:parts");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new LegacyPropertiesMigrator(consumer).migrate(input))
        .withMessage("Invalid credential: client:secret:extra:parts");
  }

  @Test
  void token() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN, "access-token-123");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.TOKEN, "access-token-123"));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.TOKEN, Basic.TOKEN);
  }

  @Test
  void tokenExpiresInMs() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN_EXPIRES_IN_MS, "300000");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual)
        .isEqualTo(
            Map.of(TokenRefresh.ACCESS_TOKEN_LIFESPAN, Duration.ofMillis(300000).toString()));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.TOKEN_EXPIRES_IN_MS, TokenRefresh.ACCESS_TOKEN_LIFESPAN);
  }

  @Test
  void tokenRefreshEnabled() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN_REFRESH_ENABLED, "true");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenRefresh.ENABLED, "true"));
    assertThat(messages).hasSize(1);
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.TOKEN_REFRESH_ENABLED, TokenRefresh.ENABLED);
  }

  @Test
  void oAuth2ServerUri() {
    Map<String, String> input =
        Map.of(OAuth2Properties.OAUTH2_SERVER_URI, "https://example.com/token");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.TOKEN_ENDPOINT, "https://example.com/token"));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use options {} {} {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(
            OAuth2Properties.OAUTH2_SERVER_URI, Basic.ISSUER_URL, "or", Basic.TOKEN_ENDPOINT);
  }

  @Test
  void scope() {
    Map<String, String> input = Map.of(OAuth2Properties.SCOPE, "read write admin");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.SCOPE, "read write admin"));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.SCOPE, Basic.SCOPE);
  }

  @Test
  void audience() {
    Map<String, String> input = Map.of(OAuth2Properties.AUDIENCE, "https://api.example.com");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenExchange.AUDIENCE, "https://api.example.com"));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.AUDIENCE, TokenExchange.AUDIENCE);
  }

  @Test
  void resource() {
    Map<String, String> input = Map.of(OAuth2Properties.RESOURCE, "urn:example:resource");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenExchange.RESOURCE, "urn:example:resource"));
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message)
        .extracting(Pair::first)
        .isEqualTo("Detected legacy property '{}', please use option {} instead.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(OAuth2Properties.RESOURCE, TokenExchange.RESOURCE);
  }

  @ParameterizedTest
  @MethodSource
  void ignoredTokenType(String tokenTypeProperty) {
    Map<String, String> input = Map.of(tokenTypeProperty, "some-value");
    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);
    assertThat(actual).isEmpty();
    assertThat(messages).hasSize(1);
    Pair<String, String[]> message = messages.get(0);
    assertThat(message).extracting(Pair::first).isEqualTo("Ignoring legacy property '{}': {}.");
    assertThat(message)
        .extracting(Pair::second)
        .asInstanceOf(array(String[].class))
        .containsExactly(tokenTypeProperty, "vended token exchange is not supported");
  }

  static Stream<Arguments> ignoredTokenType() {
    return Stream.of(
        Arguments.of(OAuth2Properties.ACCESS_TOKEN_TYPE),
        Arguments.of(OAuth2Properties.ID_TOKEN_TYPE),
        Arguments.of(OAuth2Properties.SAML1_TOKEN_TYPE),
        Arguments.of(OAuth2Properties.SAML2_TOKEN_TYPE),
        Arguments.of(OAuth2Properties.JWT_TOKEN_TYPE));
  }

  @Test
  void fullMigrationScenario() {
    Map<String, String> input = new HashMap<>();
    input.put(OAuth2Properties.CREDENTIAL, "client1:secret1");
    input.put(OAuth2Properties.TOKEN, "access-token");
    input.put(OAuth2Properties.TOKEN_EXPIRES_IN_MS, "300000");
    input.put(OAuth2Properties.TOKEN_REFRESH_ENABLED, "true");
    input.put(OAuth2Properties.OAUTH2_SERVER_URI, "https://example.com/token");
    input.put(OAuth2Properties.SCOPE, "read write");
    input.put(OAuth2Properties.AUDIENCE, "https://api.example.com");
    input.put(OAuth2Properties.RESOURCE, "urn:example:resource");
    input.put(OAuth2Properties.ACCESS_TOKEN_TYPE, "ignored");
    input.put(Basic.ISSUER_URL, "https://example.com"); // New property should be preserved
    input.put("non.oauth2.property", "ignored"); // Non-OAuth2 property should be filtered out

    Map<String, String> actual = new LegacyPropertiesMigrator(consumer).migrate(input);

    Map<String, String> expected = new HashMap<>();
    expected.put(Basic.CLIENT_ID, "client1");
    expected.put(Basic.CLIENT_SECRET, "secret1");
    expected.put(Basic.TOKEN, "access-token");
    expected.put(TokenRefresh.ACCESS_TOKEN_LIFESPAN, Duration.ofMillis(300000).toString());
    expected.put(TokenRefresh.ENABLED, "true");
    expected.put(Basic.TOKEN_ENDPOINT, "https://example.com/token");
    expected.put(Basic.SCOPE, "read write");
    expected.put(TokenExchange.AUDIENCE, "https://api.example.com");
    expected.put(TokenExchange.RESOURCE, "urn:example:resource");
    expected.put(Basic.ISSUER_URL, "https://example.com");

    assertThat(actual).containsExactlyInAnyOrderEntriesOf(expected);

    // Should have 9 log entries: 8 migration warnings + 1 ignored property warning
    assertThat(messages).hasSize(9);

    List<String> legacyProperties =
        messages.stream()
            .filter(msg -> msg.first().contains("Detected legacy property"))
            .map(Pair::second)
            .map(args -> args[0])
            .collect(Collectors.toList());

    // Verify migration warnings
    assertThat(legacyProperties)
        .containsExactlyInAnyOrder(
            OAuth2Properties.CREDENTIAL,
            OAuth2Properties.TOKEN,
            OAuth2Properties.TOKEN_EXPIRES_IN_MS,
            OAuth2Properties.TOKEN_REFRESH_ENABLED,
            OAuth2Properties.OAUTH2_SERVER_URI,
            OAuth2Properties.SCOPE,
            OAuth2Properties.AUDIENCE,
            OAuth2Properties.RESOURCE);

    List<String> ignoredProperties =
        messages.stream()
            .filter(msg -> msg.first().contains("Ignoring legacy property"))
            .map(Pair::second)
            .map(args -> args[0])
            .collect(Collectors.toList());

    // Verify ignored property warning
    assertThat(ignoredProperties).containsOnly(OAuth2Properties.ACCESS_TOKEN_TYPE);
  }

  @Test
  void noDuplicateWarnings() {
    Map<String, String> input = new HashMap<>();
    input.put(OAuth2Properties.CREDENTIAL, "client1:secret1");
    input.put(OAuth2Properties.TOKEN, "access-token");
    input.put(OAuth2Properties.TOKEN_EXPIRES_IN_MS, "300000");
    input.put(OAuth2Properties.TOKEN_REFRESH_ENABLED, "true");
    input.put(OAuth2Properties.OAUTH2_SERVER_URI, "https://example.com/token");
    input.put(OAuth2Properties.SCOPE, "read write");
    input.put(OAuth2Properties.AUDIENCE, "https://api.example.com");
    input.put(OAuth2Properties.RESOURCE, "urn:example:resource");
    input.put(OAuth2Properties.ACCESS_TOKEN_TYPE, "ignored");
    LegacyPropertiesMigrator migrator = new LegacyPropertiesMigrator(consumer);
    migrator.migrate(input);
    migrator.migrate(input);
    assertThat(messages).hasSize(9);
  }
}

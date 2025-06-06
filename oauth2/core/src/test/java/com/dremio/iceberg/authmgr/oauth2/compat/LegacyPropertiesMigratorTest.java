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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.iceberg.rest.auth.OAuth2Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;

class LegacyPropertiesMigratorTest {

  private ListAppender<ILoggingEvent> logAppender;
  private Logger logger;

  @BeforeEach
  void setUp() {
    logger = (Logger) LoggerFactory.getLogger(LegacyPropertiesMigrator.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    logger.addAppender(logAppender);
    logger.setLevel(Level.WARN);
  }

  @AfterEach
  void tearDown() {
    logger.detachAppender(logAppender);
    logAppender.stop();
  }

  @Test
  void emptyMap() {
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(Map.of());
    assertThat(actual).isEmpty();
    assertThat(logAppender.list).isEmpty();
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
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    // Only OAuth2 properties should be included
    assertThat(actual)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of(
                Basic.CLIENT_ID, "client1",
                Basic.CLIENT_SECRET, "secret"));
    assertThat(logAppender.list).isEmpty();
  }

  @ParameterizedTest
  @MethodSource
  void credential(String credentialValue, Map<String, String> expected) {
    Map<String, String> input = Map.of(OAuth2Properties.CREDENTIAL, credentialValue);
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).containsExactlyInAnyOrderEntriesOf(expected);
    assertThat(logAppender.list).hasSize(1);
    ILoggingEvent logEvent = logAppender.list.get(0);
    assertThat(logEvent.getLevel()).isEqualTo(Level.WARN);
    assertThat(logEvent.getFormattedMessage())
        .contains("Detected legacy property 'credential'")
        .contains(
            "please use options 'rest.auth.oauth2.client-id' and 'rest.auth.oauth2.client-secret' instead");
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
        .isThrownBy(() -> LegacyPropertiesMigrator.migrate(input))
        .withMessage("Invalid credential: client:secret:extra:parts");
  }

  @Test
  void token() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN, "access-token-123");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.TOKEN, "access-token-123"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'token'")
        .contains("please use option 'rest.auth.oauth2.token' instead");
  }

  @Test
  void tokenExpiresInMs() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN_EXPIRES_IN_MS, "300000");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual)
        .isEqualTo(
            Map.of(
                TokenRefresh.DEFAULT_ACCESS_TOKEN_LIFESPAN, Duration.ofMillis(300000).toString()));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'token-expires-in-ms'")
        .contains(
            "please use option 'rest.auth.oauth2.token-refresh.access-token-lifespan' instead");
  }

  @Test
  void tokenRefreshEnabled() {
    Map<String, String> input = Map.of(OAuth2Properties.TOKEN_REFRESH_ENABLED, "true");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenRefresh.ENABLED, "true"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'token-refresh-enabled'")
        .contains("please use option 'rest.auth.oauth2.token-refresh.enabled' instead");
  }

  @Test
  void oAuth2ServerUri() {
    Map<String, String> input =
        Map.of(OAuth2Properties.OAUTH2_SERVER_URI, "https://example.com/token");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.TOKEN_ENDPOINT, "https://example.com/token"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'oauth2-server-uri'")
        .contains(
            "please use options 'rest.auth.oauth2.issuer-url' and 'rest.auth.oauth2.token-endpoint' instead");
  }

  @Test
  void scope() {
    Map<String, String> input = Map.of(OAuth2Properties.SCOPE, "read write admin");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(Basic.SCOPE, "read write admin"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'scope'")
        .contains("please use option 'rest.auth.oauth2.scope' instead");
  }

  @Test
  void audience() {
    Map<String, String> input = Map.of(OAuth2Properties.AUDIENCE, "https://api.example.com");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenExchange.AUDIENCE, "https://api.example.com"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'audience'")
        .contains("please use option 'rest.auth.oauth2.token-exchange.audience' instead");
  }

  @Test
  void resource() {
    Map<String, String> input = Map.of(OAuth2Properties.RESOURCE, "urn:example:resource");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEqualTo(Map.of(TokenExchange.RESOURCE, "urn:example:resource"));
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .contains("Detected legacy property 'resource'")
        .contains("please use option 'rest.auth.oauth2.token-exchange.resource' instead");
  }

  @ParameterizedTest
  @MethodSource
  void ignoredTokenType(String tokenTypeProperty) {
    Map<String, String> input = Map.of(tokenTypeProperty, "some-value");
    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);
    assertThat(actual).isEmpty();
    assertThat(logAppender.list).hasSize(1);
    assertThat(logAppender.list.get(0).getFormattedMessage())
        .isEqualTo(
            "Ignoring legacy property '"
                + tokenTypeProperty
                + "': vended token exchange is not supported.");
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

    Map<String, String> actual = LegacyPropertiesMigrator.migrate(input);

    Map<String, String> expected = new HashMap<>();
    expected.put(Basic.CLIENT_ID, "client1");
    expected.put(Basic.CLIENT_SECRET, "secret1");
    expected.put(Basic.TOKEN, "access-token");
    expected.put(TokenRefresh.DEFAULT_ACCESS_TOKEN_LIFESPAN, Duration.ofMillis(300000).toString());
    expected.put(TokenRefresh.ENABLED, "true");
    expected.put(Basic.TOKEN_ENDPOINT, "https://example.com/token");
    expected.put(Basic.SCOPE, "read write");
    expected.put(TokenExchange.AUDIENCE, "https://api.example.com");
    expected.put(TokenExchange.RESOURCE, "urn:example:resource");
    expected.put(Basic.ISSUER_URL, "https://example.com");

    assertThat(actual).containsExactlyInAnyOrderEntriesOf(expected);

    // Should have 9 log entries: 8 migration warnings + 1 ignored property warning
    assertThat(logAppender.list).hasSize(9);

    List<String> logMessages =
        logAppender.list.stream()
            .map(ILoggingEvent::getFormattedMessage)
            .collect(Collectors.toList());

    // Verify migration warnings
    assertThat(logMessages).anyMatch(msg -> msg.contains("Detected legacy property 'credential'"));
    assertThat(logMessages).anyMatch(msg -> msg.contains("Detected legacy property 'token'"));
    assertThat(logMessages)
        .anyMatch(msg -> msg.contains("Detected legacy property 'token-expires-in-ms'"));
    assertThat(logMessages)
        .anyMatch(msg -> msg.contains("Detected legacy property 'token-refresh-enabled'"));
    assertThat(logMessages)
        .anyMatch(msg -> msg.contains("Detected legacy property 'oauth2-server-uri'"));
    assertThat(logMessages).anyMatch(msg -> msg.contains("Detected legacy property 'scope'"));
    assertThat(logMessages).anyMatch(msg -> msg.contains("Detected legacy property 'audience'"));
    assertThat(logMessages).anyMatch(msg -> msg.contains("Detected legacy property 'resource'"));

    // Verify ignored property warning
    assertThat(logMessages)
        .anyMatch(
            msg ->
                msg.contains(
                    "Ignoring legacy property 'urn:ietf:params:oauth:token-type:access_token'"));
  }
}

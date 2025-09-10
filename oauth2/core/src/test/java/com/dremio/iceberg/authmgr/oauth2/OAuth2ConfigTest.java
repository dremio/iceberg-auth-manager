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
package com.dremio.iceberg.authmgr.oauth2;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.HttpConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import io.smallrye.config.ConfigValidationException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.RestoreSystemProperties;

class OAuth2ConfigTest {

  @TempDir static Path tempDir;

  static Path tempFile;

  @BeforeAll
  static void createFile() throws IOException {
    tempFile = Files.createTempFile(tempDir, "private-key", ".pem");
  }

  @Test
  void testFromPropertiesMap() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token")
            .put(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client")
            .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "w00t")
            .put(PREFIX + '.' + BasicConfig.SCOPE, "test")
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    assertThat(config).isNotNull();
    assertThat(config.getBasicConfig().getTokenEndpoint())
        .contains(URI.create("https://example.com/token"));
    assertThat(config.getBasicConfig().getGrantType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
    assertThat(config.getBasicConfig().getClientId()).contains(new ClientID("Client"));
    assertThat(config.getBasicConfig().getClientSecret()).contains(new Secret("w00t"));
    assertThat(config.getBasicConfig().getScope()).contains(new Scope("test"));
    assertThat(config.getBasicConfig().getExtraRequestParameters()).isEmpty();
    assertThat(config.getBasicConfig().getTimeout()).isEqualTo(Duration.ofMinutes(5));
  }

  @Test
  @RestoreSystemProperties
  void testFromSystemProperties() {
    System.setProperty(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token");
    System.setProperty(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client");
    System.setProperty(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "w00t");
    System.setProperty(PREFIX + '.' + BasicConfig.SCOPE, "test");
    OAuth2Config config = OAuth2Config.from(Map.of());
    assertThat(config).isNotNull();
    assertThat(config.getBasicConfig().getTokenEndpoint())
        .contains(URI.create("https://example.com/token"));
    assertThat(config.getBasicConfig().getGrantType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
    assertThat(config.getBasicConfig().getClientId()).contains(new ClientID("Client"));
    assertThat(config.getBasicConfig().getClientSecret()).contains(new Secret("w00t"));
    assertThat(config.getBasicConfig().getScope()).contains(new Scope("test"));
    assertThat(config.getBasicConfig().getExtraRequestParameters()).isEmpty();
    assertThat(config.getBasicConfig().getTimeout()).isEqualTo(Duration.ofMinutes(5));
  }

  @Test
  void testFromUnknownProperty() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder().put(PREFIX + ".unknown", "test").build();
    assertThatThrownBy(() -> OAuth2Config.from(properties))
        .isInstanceOf(ConfigValidationException.class)
        .hasMessageContaining(
            PREFIX + ".unknown in catalog session properties does not map to any root");
  }

  @Test
  void testMerge() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token")
            .put(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client")
            .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "w00t")
            .put(PREFIX + '.' + BasicConfig.SCOPE, "test")
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    OAuth2Config child = config.merge(Map.of(PREFIX + '.' + "client-id", "Child"));
    assertThat(child.getBasicConfig().getClientId()).contains(new ClientID("Child"));
  }

  @Test
  void testMergeUnknownProperty() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token")
            .put(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client")
            .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "w00t")
            .put(PREFIX + '.' + BasicConfig.SCOPE, "test")
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    assertThatThrownBy(() -> config.merge(Map.of(PREFIX + ".unknown", "test")))
        .isInstanceOf(ConfigValidationException.class)
        .hasMessageContaining(
            PREFIX + ".unknown in child session properties does not map to any root");
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()

            // Basic
            .put(PREFIX + ".token-endpoint", "https://example.com/token")
            .put(PREFIX + ".token", "token")
            .put(PREFIX + ".grant-type", "authorization_code")
            .put(PREFIX + ".client-id", "Client")
            .put(PREFIX + ".client-secret", "w00t")
            .put(PREFIX + ".client-auth", "client_secret_post")
            .put(PREFIX + ".scope", "test")
            .put(PREFIX + ".extra-params.extra1", "param1")
            .put(PREFIX + ".extra-params.extra2", "param 2")
            .put(PREFIX + ".timeout", "PT1M")
            .put(PREFIX + ".min-timeout", "PT1M")

            // Resource Owner
            .put(ResourceOwnerConfig.PREFIX + ".username", "username")
            .put(ResourceOwnerConfig.PREFIX + ".password", "password")

            // Authorization Code
            .put(AuthorizationCodeConfig.PREFIX + ".pkce.enabled", "true")
            .put(AuthorizationCodeConfig.PREFIX + ".pkce.method", "S256")
            .put(AuthorizationCodeConfig.PREFIX + ".endpoint", "https://example.com/auth")
            .put(AuthorizationCodeConfig.PREFIX + ".callback.https", "true")
            .put(AuthorizationCodeConfig.PREFIX + ".callback.bind-port", "8080")
            .put(AuthorizationCodeConfig.PREFIX + ".callback.bind-host", "0.0.0.0")
            .put(AuthorizationCodeConfig.PREFIX + ".callback.context-path", "/callback")
            .put(AuthorizationCodeConfig.PREFIX + ".redirect-uri", "https://example.com/callback")
            .put(AuthorizationCodeConfig.PREFIX + ".ssl.key-store.path", tempFile.toString())
            .put(AuthorizationCodeConfig.PREFIX + ".ssl.key-store.password", "keystore-password")
            .put(AuthorizationCodeConfig.PREFIX + ".ssl.key-store.alias", "alias")
            .put(AuthorizationCodeConfig.PREFIX + ".ssl.protocols", "TLSv1.2")
            .put(AuthorizationCodeConfig.PREFIX + ".ssl.cipher-suites", "TLS_AES_256_GCM_SHA384")

            // Device Code
            .put(DeviceCodeConfig.PREFIX + ".endpoint", "https://example.com/device")
            .put(DeviceCodeConfig.PREFIX + ".poll-interval", "PT1M")
            .put(DeviceCodeConfig.PREFIX + ".ignore-server-poll-interval", "true")
            .put(DeviceCodeConfig.PREFIX + ".min-poll-interval", "PT1M")

            // Client Assertion
            .put(ClientAssertionConfig.PREFIX + ".issuer", "https://example.com")
            .put(ClientAssertionConfig.PREFIX + ".subject", "subject")
            .put(ClientAssertionConfig.PREFIX + ".audience", "audience")
            .put(ClientAssertionConfig.PREFIX + ".token-lifespan", "PT1M")
            .put(ClientAssertionConfig.PREFIX + ".algorithm", "RS256")
            .put(ClientAssertionConfig.PREFIX + ".private-key", tempFile.toString())

            // Token Exchange
            .put(TokenExchangeConfig.PREFIX + ".subject-token", "subject-token")
            .put(
                TokenExchangeConfig.PREFIX + ".subject-token-type",
                "urn:ietf:params:oauth:token-type:access_token")
            .put(TokenExchangeConfig.PREFIX + ".actor-token", "actor-token")
            .put(
                TokenExchangeConfig.PREFIX + ".actor-token-type",
                "urn:ietf:params:oauth:token-type:access_token")
            .put(TokenExchangeConfig.PREFIX + ".resource", "https://example.com/resource")
            .put(TokenExchangeConfig.PREFIX + ".audience", "https://example.com/resource")
            .put(
                TokenExchangeConfig.PREFIX + ".requested-token-type",
                "urn:ietf:params:oauth:token-type:access_token")
            .put(
                TokenExchangeConfig.PREFIX + ".subject-token.issuer-url",
                "https://example.com/subject")
            .put(
                TokenExchangeConfig.PREFIX + ".subject-token.token-endpoint",
                "https://example.com/subject/token")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.grant-type", "authorization_code")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.client-id", "subject-client")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.client-secret", "subject-secret")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.scope", "subject-scope")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.client-auth", "client_secret_post")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.extra-params.extra1", "param1")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.extra-params.extra2", "param 2")
            .put(TokenExchangeConfig.PREFIX + ".subject-token.timeout", "PT1M")
            .put(
                TokenExchangeConfig.PREFIX + ".actor-token.issuer-url", "https://example.com/actor")
            .put(
                TokenExchangeConfig.PREFIX + ".actor-token.token-endpoint",
                "https://example.com/actor/token")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.grant-type", "client_credentials")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.client-id", "actor-client")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.client-secret", "actor-secret")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.scope", "actor-scope")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.client-auth", "client_secret_post")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.extra-params.extra1", "param1")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.extra-params.extra2", "param 2")
            .put(TokenExchangeConfig.PREFIX + ".actor-token.timeout", "PT1M")

            // Token Refresh
            .put(TokenRefreshConfig.PREFIX + ".enabled", "true")
            .put(TokenRefreshConfig.PREFIX + ".access-token-lifespan", "PT1M")
            .put(TokenRefreshConfig.PREFIX + ".safety-window", "PT10S")
            .put(TokenRefreshConfig.PREFIX + ".idle-timeout", "PT1M")
            .put(TokenRefreshConfig.PREFIX + ".min-access-token-lifespan", "PT10S")
            .put(TokenRefreshConfig.PREFIX + ".min-refresh-delay", "PT10S")
            .put(TokenRefreshConfig.PREFIX + ".min-idle-timeout", "PT10S")

            // System
            .put(SystemConfig.PREFIX + ".agent-name", "agent-name")
            .put(SystemConfig.PREFIX + ".session-cache-timeout", "PT1H")

            // Http
            .put(HttpConfig.PREFIX + ".client-type", "APACHE")
            .put(HttpConfig.PREFIX + ".read-timeout", "PT1M")
            .put(HttpConfig.PREFIX + ".connect-timeout", "PT1M")
            .put(HttpConfig.PREFIX + ".headers.custom", "value1")
            .put(HttpConfig.PREFIX + ".compression.enabled", "true")
            .put(HttpConfig.PREFIX + ".ssl.protocols", "TLSv1.2")
            .put(HttpConfig.PREFIX + ".ssl.cipher-suites", "TLS_AES_256_GCM_SHA384")
            .put(HttpConfig.PREFIX + ".ssl.hostname-verification.enabled", "true")
            .put(HttpConfig.PREFIX + ".ssl.trust-all", "false")
            .put(HttpConfig.PREFIX + ".ssl.trust-store.path", tempFile.toString())
            .put(HttpConfig.PREFIX + ".ssl.trust-store.password", "truststore-password")
            .put(HttpConfig.PREFIX + ".proxy.host", "proxy.example.com")
            .put(HttpConfig.PREFIX + ".proxy.port", "8080")
            .put(HttpConfig.PREFIX + ".proxy.username", "user")
            .put(HttpConfig.PREFIX + ".proxy.password", "pass")
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    assertThat(config.asMap()).isEqualTo(properties);
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> OAuth2Config.from(properties))
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.PASSWORD.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            List.of(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.PASSWORD.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                ResourceOwnerConfig.PREFIX + '.' + ResourceOwnerConfig.USERNAME,
                ""),
            List.of(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.PASSWORD.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                ResourceOwnerConfig.PREFIX + '.' + ResourceOwnerConfig.USERNAME,
                "Alice"),
            List.of(
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.AUTHORIZATION_CODE.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            List.of(
                "either issuer URL or authorization endpoint must be set if grant type is 'authorization_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.DEVICE_CODE.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            List.of(
                "either issuer URL or device authorization endpoint must be set if grant type is 'urn:ietf:params:oauth:grant-type:device_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                "client_secret_jwt",
                ClientAssertionConfig.PREFIX + '.' + ClientAssertionConfig.ALGORITHM,
                "RS256",
                ClientAssertionConfig.PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY,
                tempFile.toString()),
            List.of(
                "client authentication method 'client_secret_jwt' is not compatible with JWS algorithm 'RS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.algorithm)",
                "client authentication method 'client_secret_jwt' must not have a private key configured (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.private-key)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                "private_key_jwt",
                ClientAssertionConfig.PREFIX + '.' + ClientAssertionConfig.ALGORITHM,
                "HS256"),
            List.of(
                "client authentication method 'private_key_jwt' is not compatible with JWS algorithm 'HS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.algorithm)",
                "client authentication method 'private_key_jwt' requires a private key (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.private-key)")));
  }
}

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
import com.dremio.iceberg.authmgr.oauth2.config.JwtClientAuthConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JWSAlgorithm;
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
  void testLegacyPrefixRelocation() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.ISSUER_URL, "https://example.com")
            .put(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client")
            .put(PREFIX + '.' + BasicConfig.CLIENT_AUTH, "private_key_jwt")
            .put(PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.AUTHORIZATION_CODE.getValue())
            .put(PREFIX + ".auth-code.callback-https", "true")
            .put(PREFIX + ".auth-code.callback-bind-host", "example.com")
            .put(PREFIX + ".auth-code.callback-bind-port", "8080")
            .put(PREFIX + ".auth-code.callback-context-path", "/context")
            .put(PREFIX + ".client-assertion.jwt.algorithm", "RS256")
            .put(PREFIX + ".client-assertion.jwt.private-key", tempFile.toString())
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    assertThat(config.getAuthorizationCodeConfig().isCallbackHttps()).isTrue();
    assertThat(config.getAuthorizationCodeConfig().getCallbackBindHost()).hasValue("example.com");
    assertThat(config.getAuthorizationCodeConfig().getCallbackBindPort()).hasValue(8080);
    assertThat(config.getAuthorizationCodeConfig().getCallbackContextPath()).hasValue("/context");
    assertThat(config.getJwtClientAuthConfig().getAlgorithm()).contains(JWSAlgorithm.RS256);
    assertThat(config.getJwtClientAuthConfig().getPrivateKey()).contains(tempFile);
  }

  @Test
  @RestoreSystemProperties
  void testLegacyPrefixRelocationFromSystemProperties() {
    System.setProperty(PREFIX + '.' + BasicConfig.ISSUER_URL, "https://example.com");
    System.setProperty(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client");
    System.setProperty(PREFIX + '.' + BasicConfig.CLIENT_AUTH, "private_key_jwt");
    System.setProperty(
        PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.AUTHORIZATION_CODE.getValue());
    System.setProperty(PREFIX + ".auth-code.callback-https", "true");
    System.setProperty(PREFIX + ".auth-code.callback-bind-host", "example.com");
    System.setProperty(PREFIX + ".auth-code.callback-bind-port", "8080");
    System.setProperty(PREFIX + ".auth-code.callback-context-path", "/context");
    System.setProperty(PREFIX + ".client-assertion.jwt.algorithm", "RS256");
    System.setProperty(PREFIX + ".client-assertion.jwt.private-key", tempFile.toString());
    OAuth2Config config = OAuth2Config.from(Map.of());
    assertThat(config.getAuthorizationCodeConfig().isCallbackHttps()).isTrue();
    assertThat(config.getAuthorizationCodeConfig().getCallbackBindHost()).hasValue("example.com");
    assertThat(config.getAuthorizationCodeConfig().getCallbackBindPort()).hasValue(8080);
    assertThat(config.getAuthorizationCodeConfig().getCallbackContextPath()).hasValue("/context");
    assertThat(config.getJwtClientAuthConfig().getAlgorithm()).contains(JWSAlgorithm.RS256);
    assertThat(config.getJwtClientAuthConfig().getPrivateKey()).contains(tempFile);
  }

  @Test
  void testLegacyNestedPrefixRelocation() {
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token")
            .put(PREFIX + '.' + BasicConfig.CLIENT_ID, "Client")
            .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "w00t")
            .put(PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.TOKEN_EXCHANGE.getValue())
            .put(
                "rest.auth.oauth2.token-exchange.subject-token.grant-type",
                GrantType.AUTHORIZATION_CODE.getValue())
            .put("rest.auth.oauth2.token-exchange.subject-token.auth-code.callback-https", "true")
            .build();
    OAuth2Config config = OAuth2Config.from(properties);
    assertThat(config.getTokenExchangeConfig().getSubjectTokenConfig())
        .containsEntry(BasicConfig.GRANT_TYPE, GrantType.AUTHORIZATION_CODE.getValue())
        .containsEntry(
            AuthorizationCodeConfig.GROUP_NAME + '.' + AuthorizationCodeConfig.CALLBACK_HTTPS,
            "true");
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
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.JWT_BEARER.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            List.of(
                "either assertion, assertion file or dynamic assertion configuration must be set if grant type is 'urn:ietf:params:oauth:grant-type:jwt-bearer' (rest.auth.oauth2.jwt-bearer.assertion / rest.auth.oauth2.jwt-bearer.assertion-file)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.TOKEN_EXCHANGE.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            List.of(
                "either subject token, subject token file or dynamic subject token configuration must be set if grant type is 'urn:ietf:params:oauth:grant-type:token-exchange' (rest.auth.oauth2.token-exchange.subject-token / rest.auth.oauth2.token-exchange.subject-token-file)")),
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
                JwtClientAuthConfig.PREFIX + '.' + JwtClientAuthConfig.ALGORITHM,
                "RS256",
                JwtClientAuthConfig.PREFIX + '.' + JwtClientAuthConfig.PRIVATE_KEY,
                tempFile.toString()),
            List.of(
                "client authentication method 'client_secret_jwt' is not compatible with JWS algorithm 'RS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-auth.jwt.algorithm)",
                "client authentication method 'client_secret_jwt' must not have a private key configured (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-auth.jwt.private-key)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                "private_key_jwt",
                JwtClientAuthConfig.PREFIX + '.' + JwtClientAuthConfig.ALGORITHM,
                "HS256"),
            List.of(
                "client authentication method 'private_key_jwt' is not compatible with JWS algorithm 'HS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-auth.jwt.algorithm)",
                "client authentication method 'private_key_jwt' requires a private key (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-auth.jwt.private-key)")));
  }
}

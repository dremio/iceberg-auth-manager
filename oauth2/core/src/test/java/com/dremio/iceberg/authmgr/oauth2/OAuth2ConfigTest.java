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

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
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

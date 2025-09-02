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

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.System;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class OAuth2ConfigTest {

  @TempDir static Path tempDir;

  static Path tempFile;

  @BeforeAll
  static void createFile() throws IOException {
    tempFile = Files.createTempFile(tempDir, "private-key", ".pem");
  }

  /**
   * Tests that two {@link OAuth2Config} instances created from the same properties are equal.
   *
   * <p>Only the system config should be ignored for equality.
   */
  @Test
  void testEqualsHashCode() {
    Map<String, String> properties1 =
        ImmutableMap.<String, String>builder()
            .put(Basic.GRANT_TYPE, "authorization_code")
            .put(Basic.ISSUER_URL, "https://example.com")
            .put(Basic.CLIENT_ID, "client-id")
            .put(Basic.CLIENT_SECRET, "client-secret")
            .put(Basic.CLIENT_AUTH, "client_secret_basic")
            .put(Basic.SCOPE, "scope")
            .put(Basic.TOKEN_ENDPOINT, "https://example.com/token")
            .put(Basic.TIMEOUT, "PT1M")
            .put(Basic.TOKEN, "token")
            .put(Basic.EXTRA_PARAMS_PREFIX + "extra1", "value1")
            .put(AuthorizationCode.CALLBACK_BIND_PORT, "8080")
            .put(AuthorizationCode.CALLBACK_BIND_HOST, "localhost")
            .put(AuthorizationCode.CALLBACK_CONTEXT_PATH, "/callback")
            .put(AuthorizationCode.REDIRECT_URI, "https://example.com/callback")
            .put(AuthorizationCode.PKCE_ENABLED, "true")
            .put(AuthorizationCode.PKCE_METHOD, "S256")
            .put(AuthorizationCode.ENDPOINT, "https://example.com/auth")
            .put(DeviceCode.ENDPOINT, "https://example.com/device")
            .put(DeviceCode.POLL_INTERVAL, "PT1M")
            .put(ClientAssertion.ISSUER, "https://example.com/token")
            .put(ClientAssertion.SUBJECT, "subject")
            .put(ClientAssertion.AUDIENCE, "audience")
            .put(ClientAssertion.TOKEN_LIFESPAN, "PT1H")
            .put(ClientAssertion.EXTRA_CLAIMS_PREFIX + "key1", "value1")
            .put(ClientAssertion.ALGORITHM, "RS256")
            .put(ClientAssertion.PRIVATE_KEY, tempFile.toString())
            .put(ResourceOwner.USERNAME, "username")
            .put(ResourceOwner.PASSWORD, "password")
            .put(TokenRefresh.ENABLED, "true")
            .put(TokenRefresh.ACCESS_TOKEN_LIFESPAN, "PT1H")
            .put(TokenRefresh.SAFETY_WINDOW, "PT10S")
            .put(TokenRefresh.IDLE_TIMEOUT, "PT1M")
            .put(TokenExchange.SUBJECT_TOKEN, "subject-token")
            .put(TokenExchange.SUBJECT_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token")
            .put(TokenExchange.ACTOR_TOKEN, "actor-token")
            .put(TokenExchange.ACTOR_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token")
            .put(
                TokenExchange.REQUESTED_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token")
            .put(
                TokenExchange.SUBJECT_CONFIG_PREFIX + "token-endpoint", "https://example.com/token")
            .put(TokenExchange.ACTOR_CONFIG_PREFIX + "token-endpoint", "https://example.com/token")
            .put(TokenExchange.RESOURCE, "https://example.com/resource")
            .put(TokenExchange.AUDIENCE, "audience")
            .put(System.AGENT_NAME, "agent-name1")
            .put(System.HTTP_CLIENT_TYPE, "default")
            .put(System.SESSION_CACHE_TIMEOUT, "PT1H")
            .build();
    Map<String, String> properties2 =
        ImmutableMap.<String, String>builder()
            .putAll(properties1)
            // system settings should not influence config equality
            .put(System.AGENT_NAME, "agent-name2")
            .put(System.SESSION_CACHE_TIMEOUT, "PT2H")
            .put(System.HTTP_CLIENT_TYPE, "apache")
            .buildKeepingLast();
    OAuth2Config config1 = OAuth2Config.builder().from(properties1).build();
    OAuth2Config config2 = OAuth2Config.builder().from(properties2).build();
    assertThat(config1).hasSameHashCodeAs(config2);
    assertThat(config1).isEqualTo(config2);
  }

  @ParameterizedTest
  @MethodSource
  void testValidate(OAuth2Config.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .build()),
            asList(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .build())
                .resourceOwnerConfig(ResourceOwnerConfig.builder().username("").build()),
            asList(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .build())
                .resourceOwnerConfig(ResourceOwnerConfig.builder().username("Alice").build()),
            singletonList(
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .build()),
            singletonList(
                "either issuer URL or authorization endpoint must be set if grant type is 'authorization_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.DEVICE_CODE)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .build()),
            singletonList(
                "either issuer URL or device authorization endpoint must be set if grant type is 'urn:ietf:params:oauth:grant-type:device_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientSecret(new Secret("s3cr3t"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                        .build())
                .clientAssertionConfig(
                    ClientAssertionConfig.builder()
                        .algorithm(JWSAlgorithm.RS256)
                        .privateKey(tempFile)
                        .build()),
            List.of(
                "client authentication method 'client_secret_jwt' is not compatible with JWS algorithm 'RS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.algorithm)",
                "client authentication method 'client_secret_jwt' must not have a private key configured (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.private-key)")),
        Arguments.of(
            OAuth2Config.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId(new ClientID("Client1"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                        .build())
                .clientAssertionConfig(
                    ClientAssertionConfig.builder().algorithm(JWSAlgorithm.HS256).build()),
            List.of(
                "client authentication method 'private_key_jwt' is not compatible with JWS algorithm 'HS256' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.algorithm)",
                "client authentication method 'private_key_jwt' requires a private key (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-assertion.jwt.private-key)")));
  }
}

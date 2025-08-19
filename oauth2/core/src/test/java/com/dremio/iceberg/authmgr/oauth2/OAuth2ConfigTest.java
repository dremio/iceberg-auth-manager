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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
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
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
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

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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_ID;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_SECRET;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.GRANT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN_ENDPOINT;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class BasicConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(BasicConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t")),
            singletonList(
                "either issuer URL or token endpoint must be set (rest.auth.oauth2.issuer-url / rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .issuerUrl(URI.create("realms/master")),
            singletonList("Issuer URL must not be relative (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .issuerUrl(URI.create("https://example.com?query")),
            singletonList("Issuer URL must not have a query part (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .issuerUrl(URI.create("https://example.com#fragment")),
            singletonList(
                "Issuer URL must not have a fragment part (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .tokenEndpoint(URI.create("https://example.com?query")),
            singletonList(
                "Token endpoint must not have a query part (rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .tokenEndpoint(URI.create("https://example.com#fragment")),
            singletonList(
                "Token endpoint must not have a fragment part (rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            BasicConfig.builder()
                .clientSecret(new Secret("secret"))
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList("client ID must not be empty (rest.auth.oauth2.client-id)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_basic' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_post' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_jwt' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "client secret must not be set when client authentication is 'private_key_jwt' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "client secret must not be set when client authentication is 'none' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .tokenEndpoint(URI.create("https://example.com/token")),
            singletonList(
                "grant type must not be 'client_credentials' when client authentication is 'none' (rest.auth.oauth2.client-auth / rest.auth.oauth2.grant-type)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .tokenEndpoint(URI.create("https://example.com/token"))
                .grantType(GrantType.REFRESH_TOKEN),
            singletonList(
                "grant type must be one of: 'client_credentials', 'password', 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:ietf:params:oauth:grant-type:token-exchange' (rest.auth.oauth2.grant-type)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .tokenEndpoint(URI.create("https://example.com/token"))
                .clientAuthenticationMethod(new ClientAuthenticationMethod("unknown")),
            singletonList(
                "client authentication method must be one of: 'none', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt' (rest.auth.oauth2.client-auth)")),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("s3cr3t"))
                .issuerUrl(URI.create("https://example.com"))
                .timeout(Duration.ofSeconds(1)),
            singletonList(
                "timeout must be greater than or equal to PT30S (rest.auth.oauth2.timeout)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, BasicConfig expected, Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      BasicConfig actual = BasicConfig.builder().from(properties).build();
      assertThat(actual).usingRecursiveComparison().isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> BasicConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            ImmutableMap.builder()
                .put(ISSUER_URL, "https://example.com/")
                .put(TOKEN_ENDPOINT, "https://example.com/token")
                .put(GRANT_TYPE, "authorization_code")
                .put(CLIENT_ID, "Client")
                .put(CLIENT_SECRET, "w00t")
                .put(SCOPE, "test")
                .put(EXTRA_PARAMS_PREFIX + "extra1", "param1")
                .put(EXTRA_PARAMS_PREFIX + "extra2", "param 2")
                .put(EXTRA_PARAMS_PREFIX + "extra3", "") // empty
                .put(EXTRA_PARAMS_PREFIX, "") // malformed
                .put(TIMEOUT, "PT1M")
                .build(),
            BasicConfig.builder()
                .issuerUrl(URI.create("https://example.com/"))
                .tokenEndpoint(URI.create("https://example.com/token"))
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientId(new ClientID("Client"))
                .clientSecret(new Secret("w00t"))
                .scope(new Scope("test"))
                .extraRequestParameters(ImmutableMap.of("extra1", "param1", "extra2", "param 2"))
                .timeout(Duration.ofMinutes(1))
                .build(),
            null),
        // Token
        Arguments.of(
            ImmutableMap.builder()
                .put(TOKEN, "token")
                .put(TOKEN_ENDPOINT, "https://example.com/token")
                .build(),
            BasicConfig.builder()
                .token(new BearerAccessToken("token"))
                .tokenEndpoint(URI.create("https://example.com/token"))
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(BasicConfig base, Map<String, String> properties, BasicConfig expected) {
    BasicConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            BasicConfig.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .scope(TestConstants.SCOPE1)
                .extraRequestParameters(Map.of("extra1", "value1"))
                .build(),
            Map.of(),
            BasicConfig.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .scope(TestConstants.SCOPE1)
                .extraRequestParameters(Map.of("extra1", "value1"))
                .build()),
        Arguments.of(
            BasicConfig.builder()
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .build(),
            Map.of(
                Basic.GRANT_TYPE,
                GrantType.CLIENT_CREDENTIALS.getValue(),
                Basic.TOKEN_ENDPOINT,
                "https://example1.com/token",
                Basic.SCOPE,
                TestConstants.SCOPE1.toString(),
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1"),
            BasicConfig.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .scope(TestConstants.SCOPE1)
                .extraRequestParameters(Map.of("extra1", "value1"))
                .build()),
        Arguments.of(
            BasicConfig.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .scope(TestConstants.SCOPE1)
                .extraRequestParameters(Map.of("extra1", "value1", "extra2", "value2"))
                .build(),
            Map.of(
                Basic.GRANT_TYPE,
                GrantType.CLIENT_CREDENTIALS.getValue(),
                Basic.CLIENT_ID,
                "Client2",
                Basic.CLIENT_SECRET,
                "secret2",
                Basic.ISSUER_URL,
                "https://example2.com",
                Basic.TOKEN_ENDPOINT,
                "https://example2.com/token",
                Basic.SCOPE,
                TestConstants.SCOPE2.toString(),
                Basic.EXTRA_PARAMS_PREFIX + "extra2",
                "value2",
                Basic.EXTRA_PARAMS_PREFIX + "extra3",
                "value3"),
            BasicConfig.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientId(new ClientID("Client2"))
                .clientSecret(new Secret("secret2"))
                .issuerUrl(URI.create("https://example2.com"))
                .tokenEndpoint(URI.create("https://example2.com/token"))
                .scope(TestConstants.SCOPE2)
                .extraRequestParameters(
                    Map.of("extra1", "value1", "extra2", "value2", "extra3", "value3"))
                .build()),
        Arguments.of(
            BasicConfig.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .token(new BearerAccessToken("token"))
                .clientId(new ClientID("Client1"))
                .clientSecret(new Secret("secret1"))
                .issuerUrl(URI.create("https://example1.com"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .scope(TestConstants.SCOPE1)
                .extraRequestParameters(Map.of("extra1", "value1", "extra2", "value2"))
                .build(),
            Map.of(
                Basic.TOKEN,
                "",
                Basic.CLIENT_AUTH,
                "none",
                Basic.CLIENT_SECRET,
                "",
                Basic.ISSUER_URL,
                "",
                Basic.SCOPE,
                "",
                Basic.EXTRA_PARAMS_PREFIX + "extra2",
                "",
                Basic.EXTRA_PARAMS_PREFIX + "extra3",
                ""),
            BasicConfig.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientId(new ClientID("Client1"))
                .tokenEndpoint(URI.create("https://example1.com/token"))
                .extraRequestParameters(Map.of("extra1", "value1"))
                .build()));
  }
}

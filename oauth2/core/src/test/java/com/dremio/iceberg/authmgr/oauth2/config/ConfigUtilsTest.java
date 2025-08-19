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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import java.net.URI;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ConfigUtilsTest {

  @ParameterizedTest
  @MethodSource
  void parseGrantType(String grantTypeString, GrantType expectedGrantType) {
    assertThat(ConfigUtils.parseGrantType(grantTypeString)).isEqualTo(expectedGrantType);
  }

  static Stream<Arguments> parseGrantType() {
    return Stream.of(
        Arguments.of("authorization_code", GrantType.AUTHORIZATION_CODE),
        Arguments.of("client_credentials", GrantType.CLIENT_CREDENTIALS),
        Arguments.of("refresh_token", GrantType.REFRESH_TOKEN),
        Arguments.of("password", GrantType.PASSWORD),
        Arguments.of("urn:ietf:params:oauth:grant-type:token-exchange", GrantType.TOKEN_EXCHANGE),
        Arguments.of("urn:ietf:params:oauth:grant-type:device_code", GrantType.DEVICE_CODE),
        Arguments.of("custom_grant_type", new GrantType("custom_grant_type")));
  }

  @Test
  void parseGrantTypeMalformed() {
    assertThatThrownBy(() -> ConfigUtils.parseGrantType("  "))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource
  void parseTokenTypeURI(String tokenTypeString, TokenTypeURI expectedTokenType) {
    assertThat(ConfigUtils.parseTokenTypeURI(tokenTypeString)).isEqualTo(expectedTokenType);
  }

  static Stream<Arguments> parseTokenTypeURI() throws ParseException {
    return Stream.of(
        Arguments.of("urn:ietf:params:oauth:token-type:access_token", TokenTypeURI.ACCESS_TOKEN),
        Arguments.of("urn:ietf:params:oauth:token-type:refresh_token", TokenTypeURI.REFRESH_TOKEN),
        Arguments.of("urn:ietf:params:oauth:token-type:id_token", TokenTypeURI.ID_TOKEN),
        Arguments.of(
            "urn:ietf:params:oauth:token-type:custom",
            TokenTypeURI.parse("urn:ietf:params:oauth:token-type:custom")));
  }

  @Test
  void parseTokenTypeURIMalformed() {
    assertThatThrownBy(() -> ConfigUtils.parseTokenTypeURI("http://[invalid"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource
  void parseAudienceList(String input, List<Audience> expectedAudiences) {
    List<Audience> audiences = ConfigUtils.parseAudienceList(input);
    assertThat(audiences).isEqualTo(expectedAudiences);
  }

  static Stream<Arguments> parseAudienceList() {
    return Stream.of(
        Arguments.of(null, List.of()),
        Arguments.of("", List.of()),
        Arguments.of("   ", List.of()),
        // single audience
        Arguments.of("https://api.example.com", List.of(new Audience("https://api.example.com"))),
        // multiple audiences
        Arguments.of(
            "https://api.example.com https://auth.example.com",
            List.of(
                new Audience("https://api.example.com"), new Audience("https://auth.example.com"))),
        // extra whitespace
        Arguments.of(
            "  https://api.example.com    https://auth.example.com  ",
            List.of(
                new Audience("https://api.example.com"),
                new Audience("https://auth.example.com"))));
  }

  @ParameterizedTest
  @MethodSource
  void parseUriList(String input, List<URI> expectedUris) {
    List<URI> uris = ConfigUtils.parseUriList(input);
    assertThat(uris).isEqualTo(expectedUris);
  }

  static Stream<Arguments> parseUriList() {
    return Stream.of(
        Arguments.of(null, List.of()),
        Arguments.of("", List.of()),
        Arguments.of("   ", List.of()),
        // single URI
        Arguments.of(
            "https://example.com/callback", List.of(URI.create("https://example.com/callback"))),
        // multiple URIs
        Arguments.of(
            "https://example.com/callback https://example.com/callback2",
            List.of(
                URI.create("https://example.com/callback"),
                URI.create("https://example.com/callback2"))),
        // extra whitespace
        Arguments.of(
            "  https://example.com/callback    https://example.com/callback2  ",
            List.of(
                URI.create("https://example.com/callback"),
                URI.create("https://example.com/callback2"))));
  }

  @Test
  void parseUriListMalformed() {
    assertThatThrownBy(() -> ConfigUtils.parseUriList("http://[invalid"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource
  void requiresClientSecret(ClientAuthenticationMethod method, boolean expectedResult) {
    assertThat(ConfigUtils.requiresClientSecret(method)).isEqualTo(expectedResult);
  }

  static Stream<Arguments> requiresClientSecret() {
    return Stream.of(
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, true),
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_POST, true),
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_JWT, true),
        Arguments.of(ClientAuthenticationMethod.NONE, false),
        Arguments.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT, false));
  }

  @ParameterizedTest
  @MethodSource
  void requiresJwsAlgorithm(ClientAuthenticationMethod method, boolean expectedResult) {
    assertThat(ConfigUtils.requiresJwsAlgorithm(method)).isEqualTo(expectedResult);
  }

  static Stream<Arguments> requiresJwsAlgorithm() {
    return Stream.of(
        Arguments.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT, true),
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_JWT, true),
        Arguments.of(ClientAuthenticationMethod.NONE, false),
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, false),
        Arguments.of(ClientAuthenticationMethod.CLIENT_SECRET_POST, false));
  }

  @ParameterizedTest
  @MethodSource
  void requiresUserInteraction(GrantType grantType, boolean expectedResult) {
    assertThat(ConfigUtils.requiresUserInteraction(grantType)).isEqualTo(expectedResult);
  }

  static Stream<Arguments> requiresUserInteraction() {
    return Stream.of(
        Arguments.of(GrantType.AUTHORIZATION_CODE, true),
        Arguments.of(GrantType.DEVICE_CODE, true),
        Arguments.of(GrantType.CLIENT_CREDENTIALS, false),
        Arguments.of(GrantType.REFRESH_TOKEN, false),
        Arguments.of(GrantType.PASSWORD, false),
        Arguments.of(GrantType.TOKEN_EXCHANGE, false));
  }
}

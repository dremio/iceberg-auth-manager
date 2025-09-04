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

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class ConfigUtilsTest {

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

  @ParameterizedTest
  @ValueSource(strings = {"a,b,c", "a, b, c", "  a  , b  , c  "})
  void parseCommaSeparatedList(String text) {
    assertThat(ConfigUtils.parseCommaSeparatedList(text)).containsExactly("a", "b", "c");
  }

  @Test
  void prefixedMap() {
    assertThat(ConfigUtils.prefixedMap(Map.of("a", "1", "b", "2"), "prefix"))
        .isEqualTo(Map.of("prefix.a", "1", "prefix.b", "2"));
  }
}

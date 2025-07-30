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
package com.dremio.iceberg.authmgr.oauth2.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class GrantTypeTest {

  @ParameterizedTest
  @MethodSource("configNameTestCases")
  void testFromConfigName(String configName, GrantType expectedGrantType) {
    assertThat(GrantType.fromConfigName(configName)).isEqualTo(expectedGrantType);
  }

  @Test
  void testFromConfigNameInvalidName() {
    assertThatThrownBy(() -> GrantType.fromConfigName(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Grant type name must not be null");
    assertThatThrownBy(() -> GrantType.fromConfigName(""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unknown grant type: ");
    assertThatThrownBy(() -> GrantType.fromConfigName("invalid"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unknown grant type: invalid");
  }

  @ParameterizedTest
  @MethodSource("requiresUserInteractionTestCases")
  void testRequiresUserInteraction(GrantType grantType, boolean expectedRequiresUserInteraction) {
    assertThat(grantType.requiresUserInteraction()).isEqualTo(expectedRequiresUserInteraction);
  }

  @ParameterizedTest
  @MethodSource("initialTestCases")
  void testInitial(GrantType grantType, boolean expectedInitial) {
    assertThat(grantType.isInitial()).isEqualTo(expectedInitial);
  }

  static Stream<Arguments> configNameTestCases() {
    return Stream.of(
        // Test canonical names
        Arguments.of("client_credentials", GrantType.CLIENT_CREDENTIALS),
        Arguments.of("password", GrantType.PASSWORD),
        Arguments.of("authorization_code", GrantType.AUTHORIZATION_CODE),
        Arguments.of("refresh_token", GrantType.REFRESH_TOKEN),
        Arguments.of("urn:ietf:params:oauth:grant-type:device_code", GrantType.DEVICE_CODE),
        Arguments.of("urn:ietf:params:oauth:grant-type:token-exchange", GrantType.TOKEN_EXCHANGE),
        // Test common names
        Arguments.of("device_code", GrantType.DEVICE_CODE),
        Arguments.of("token_exchange", GrantType.TOKEN_EXCHANGE),
        // Test case-insensitive behavior for common names
        Arguments.of("CLIENT_CREDENTIALS", GrantType.CLIENT_CREDENTIALS),
        Arguments.of("PASSWORD", GrantType.PASSWORD),
        Arguments.of("AUTHORIZATION_CODE", GrantType.AUTHORIZATION_CODE),
        Arguments.of("DEVICE_CODE", GrantType.DEVICE_CODE),
        Arguments.of("REFRESH_TOKEN", GrantType.REFRESH_TOKEN),
        Arguments.of("TOKEN_EXCHANGE", GrantType.TOKEN_EXCHANGE),
        Arguments.of("Device_Code", GrantType.DEVICE_CODE),
        Arguments.of("Token_Exchange", GrantType.TOKEN_EXCHANGE));
  }

  static Stream<Arguments> requiresUserInteractionTestCases() {
    return Stream.of(
        Arguments.of(GrantType.CLIENT_CREDENTIALS, false),
        Arguments.of(GrantType.PASSWORD, false),
        Arguments.of(GrantType.AUTHORIZATION_CODE, true),
        Arguments.of(GrantType.DEVICE_CODE, true),
        Arguments.of(GrantType.REFRESH_TOKEN, false),
        Arguments.of(GrantType.TOKEN_EXCHANGE, false));
  }

  static Stream<Arguments> initialTestCases() {
    return Stream.of(
        Arguments.of(GrantType.CLIENT_CREDENTIALS, true),
        Arguments.of(GrantType.PASSWORD, true),
        Arguments.of(GrantType.AUTHORIZATION_CODE, true),
        Arguments.of(GrantType.DEVICE_CODE, true),
        Arguments.of(GrantType.REFRESH_TOKEN, false),
        Arguments.of(GrantType.TOKEN_EXCHANGE, true));
  }
}

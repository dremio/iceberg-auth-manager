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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_BIND_HOST;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_BIND_PORT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_CONTEXT_PATH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.PKCE_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.PKCE_TRANSFORMATION;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.REDIRECT_URI;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.TIMEOUT;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class AuthorizationCodeConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(AuthorizationCodeConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            AuthorizationCodeConfig.builder().authorizationEndpoint(URI.create("/auth")),
            singletonList(
                "authorization code flow: authorization endpoint must not be relative (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com?query")),
            singletonList(
                "authorization code flow: authorization endpoint must not have a query part (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com#fragment")),
            singletonList(
                "authorization code flow: authorization endpoint must not have a fragment part (rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com"))
                .callbackBindPort(-1),
            singletonList(
                "authorization code flow: callback bind port must be between 0 and 65535 (inclusive) (rest.auth.oauth2.auth-code.callback-bind-port)")),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com"))
                .timeout(Duration.ofSeconds(1)),
            singletonList(
                "authorization code flow: timeout must be greater than or equal to PT30S (rest.auth.oauth2.auth-code.timeout)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties,
      AuthorizationCodeConfig expected,
      Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      AuthorizationCodeConfig actual = AuthorizationCodeConfig.builder().from(properties).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> AuthorizationCodeConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            Map.of(
                ENDPOINT,
                "https://example.com/auth",
                CALLBACK_BIND_PORT,
                "8080",
                CALLBACK_BIND_HOST,
                "1.2.3.4",
                TIMEOUT,
                "PT30S",
                PKCE_ENABLED,
                "false",
                PKCE_TRANSFORMATION,
                "plain"),
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .timeout(Duration.ofSeconds(30))
                .pkceEnabled(false)
                .pkceTransformation(PkceTransformation.PLAIN)
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      AuthorizationCodeConfig base,
      Map<String, String> properties,
      AuthorizationCodeConfig expected) {
    AuthorizationCodeConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            AuthorizationCodeConfig.builder().build(),
            Map.of(
                ENDPOINT,
                "https://example.com/auth",
                CALLBACK_BIND_PORT,
                "8080",
                CALLBACK_BIND_HOST,
                "1.2.3.4",
                CALLBACK_CONTEXT_PATH,
                "/callback",
                REDIRECT_URI,
                "https://example.com/callback",
                TIMEOUT,
                "PT30S",
                PKCE_ENABLED,
                "false",
                PKCE_TRANSFORMATION,
                "plain"),
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .callbackContextPath("/callback")
                .redirectUri(URI.create("https://example.com/callback"))
                .timeout(Duration.ofSeconds(30))
                .pkceEnabled(false)
                .pkceTransformation(PkceTransformation.PLAIN)
                .build()),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .callbackContextPath("/callback")
                .redirectUri(URI.create("https://example.com/callback"))
                .timeout(Duration.ofSeconds(30))
                .pkceEnabled(false)
                .pkceTransformation(PkceTransformation.PLAIN)
                .build(),
            Map.of(),
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .callbackContextPath("/callback")
                .redirectUri(URI.create("https://example.com/callback"))
                .timeout(Duration.ofSeconds(30))
                .pkceEnabled(false)
                .pkceTransformation(PkceTransformation.PLAIN)
                .build()),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .callbackContextPath("/callback")
                .redirectUri(URI.create("https://example.com/callback"))
                .timeout(Duration.ofSeconds(30))
                .pkceEnabled(false)
                .pkceTransformation(PkceTransformation.PLAIN)
                .build(),
            Map.of(
                ENDPOINT,
                "https://example2.com/auth",
                CALLBACK_BIND_PORT,
                "8081",
                CALLBACK_BIND_HOST,
                "2.3.4.5",
                CALLBACK_CONTEXT_PATH,
                "/callback2",
                REDIRECT_URI,
                "https://example2.com/callback",
                TIMEOUT,
                "PT60S",
                PKCE_ENABLED,
                "true",
                PKCE_TRANSFORMATION,
                "S256"),
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example2.com/auth"))
                .callbackBindPort(8081)
                .callbackBindHost("2.3.4.5")
                .callbackContextPath("/callback2")
                .redirectUri(URI.create("https://example2.com/callback"))
                .timeout(Duration.ofSeconds(60))
                .pkceEnabled(true)
                .pkceTransformation(PkceTransformation.S256)
                .build()),
        Arguments.of(
            AuthorizationCodeConfig.builder()
                .authorizationEndpoint(URI.create("https://example.com/auth"))
                .callbackBindPort(8080)
                .callbackBindHost("1.2.3.4")
                .callbackContextPath("/callback")
                .redirectUri(URI.create("https://example.com/callback"))
                .timeout(Duration.ofSeconds(30))
                .build(),
            Map.of(
                ENDPOINT,
                "",
                CALLBACK_BIND_PORT,
                "",
                CALLBACK_BIND_HOST,
                "",
                CALLBACK_CONTEXT_PATH,
                "",
                REDIRECT_URI,
                "",
                TIMEOUT,
                "",
                PKCE_ENABLED,
                "",
                PKCE_TRANSFORMATION,
                ""),
            AuthorizationCodeConfig.builder().build()));
  }
}

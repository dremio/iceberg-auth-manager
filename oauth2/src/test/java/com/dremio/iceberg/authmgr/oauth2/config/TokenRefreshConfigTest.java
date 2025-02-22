/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.ACCESS_TOKEN_LIFESPAN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.IDLE_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.SAFETY_WINDOW;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenRefreshConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(TokenRefreshConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            TokenRefreshConfig.builder().accessTokenLifespan(Duration.ofSeconds(2)),
            asList(
                "access token lifespan must be greater than or equal to PT30S (rest.auth.oauth2.token-refresh.access-token-lifespan)",
                "refresh safety window must be less than the access token lifespan (rest.auth.oauth2.token-refresh.safety-window / rest.auth.oauth2.token-refresh.access-token-lifespan)")),
        Arguments.of(
            TokenRefreshConfig.builder().safetyWindow(Duration.ofMillis(100)),
            singletonList(
                "refresh safety window must be greater than or equal to PT5S (rest.auth.oauth2.token-refresh.safety-window)")),
        Arguments.of(
            TokenRefreshConfig.builder()
                .safetyWindow(Duration.ofMinutes(10))
                .accessTokenLifespan(Duration.ofMinutes(5)),
            singletonList(
                "refresh safety window must be less than the access token lifespan (rest.auth.oauth2.token-refresh.safety-window / rest.auth.oauth2.token-refresh.access-token-lifespan)")),
        Arguments.of(
            TokenRefreshConfig.builder().idleTimeout(Duration.ofMillis(100)),
            singletonList(
                "token refresh idle timeout must be greater than or equal to PT30S (rest.auth.oauth2.token-refresh.idle-timeout)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, TokenRefreshConfig expected, Throwable expectedThrowable) {
    if (properties != null && expected != null) {
      TokenRefreshConfig actual = TokenRefreshConfig.builder().from(properties).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> TokenRefreshConfig.builder().from(properties));
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
                ENABLED,
                "false",
                ACCESS_TOKEN_LIFESPAN,
                "PT1H",
                SAFETY_WINDOW,
                "PT10S",
                IDLE_TIMEOUT,
                "PT1M"),
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      TokenRefreshConfig base, Map<String, String> properties, TokenRefreshConfig expected) {
    TokenRefreshConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            TokenRefreshConfig.builder().build(),
            Map.of(
                ENABLED,
                "false",
                ACCESS_TOKEN_LIFESPAN,
                "PT1H",
                SAFETY_WINDOW,
                "PT10S",
                IDLE_TIMEOUT,
                "PT1M"),
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build()),
        Arguments.of(
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build(),
            Map.of(),
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build()),
        Arguments.of(
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build(),
            Map.of(
                ENABLED,
                "true",
                ACCESS_TOKEN_LIFESPAN,
                "PT2H",
                SAFETY_WINDOW,
                "PT20S",
                IDLE_TIMEOUT,
                "PT2M"),
            TokenRefreshConfig.builder()
                .enabled(true)
                .accessTokenLifespan(Duration.ofHours(2))
                .safetyWindow(Duration.ofSeconds(20))
                .idleTimeout(Duration.ofMinutes(2))
                .build()),
        Arguments.of(
            TokenRefreshConfig.builder()
                .enabled(false)
                .accessTokenLifespan(Duration.ofHours(1))
                .safetyWindow(Duration.ofSeconds(10))
                .idleTimeout(Duration.ofMinutes(1))
                .build(),
            Map.of(ENABLED, "", ACCESS_TOKEN_LIFESPAN, "", SAFETY_WINDOW, "", IDLE_TIMEOUT, ""),
            TokenRefreshConfig.builder().build()));
  }
}

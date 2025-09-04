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

import static com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig.ACCESS_TOKEN_LIFESPAN;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig.IDLE_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig.SAFETY_WINDOW;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenRefreshConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenRefreshConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenRefreshConfig config = smallRyeConfig.getConfigMapping(TokenRefreshConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(PREFIX + '.' + ACCESS_TOKEN_LIFESPAN, "PT2S"),
            asList(
                "access token lifespan must be greater than or equal to PT30S (rest.auth.oauth2.token-refresh.access-token-lifespan)",
                "refresh safety window must be less than the access token lifespan (rest.auth.oauth2.token-refresh.safety-window / rest.auth.oauth2.token-refresh.access-token-lifespan)")),
        Arguments.of(
            Map.of(PREFIX + '.' + SAFETY_WINDOW, "PT0.1S"),
            singletonList(
                "refresh safety window must be greater than or equal to PT5S (rest.auth.oauth2.token-refresh.safety-window)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + SAFETY_WINDOW,
                "PT10M",
                PREFIX + '.' + ACCESS_TOKEN_LIFESPAN,
                "PT5M"),
            singletonList(
                "refresh safety window must be less than the access token lifespan (rest.auth.oauth2.token-refresh.safety-window / rest.auth.oauth2.token-refresh.access-token-lifespan)")),
        Arguments.of(
            Map.of(PREFIX + '.' + IDLE_TIMEOUT, "PT0.1S"),
            singletonList(
                "token refresh idle timeout must be greater than or equal to PT30S (rest.auth.oauth2.token-refresh.idle-timeout)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        Map.of(
            PREFIX + '.' + ENABLED, "true",
            PREFIX + '.' + ACCESS_TOKEN_LIFESPAN, "PT1M",
            PREFIX + '.' + SAFETY_WINDOW, "PT10S",
            PREFIX + '.' + IDLE_TIMEOUT, "PT1M",
            PREFIX + '.' + "min-access-token-lifespan", "PT10S",
            PREFIX + '.' + "min-refresh-delay", "PT10S",
            PREFIX + '.' + "min-idle-timeout", "PT10S");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(TokenRefreshConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    TokenRefreshConfig config = smallRyeConfig.getConfigMapping(TokenRefreshConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}

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

import static com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig.POLL_INTERVAL;
import static com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig.PREFIX;
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

class DeviceCodeConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(DeviceCodeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    DeviceCodeConfig config = smallRyeConfig.getConfigMapping(DeviceCodeConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "/auth"),
            singletonList(
                "device code flow: device authorization endpoint must not be relative (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "https://example.com?query"),
            singletonList(
                "device code flow: device authorization endpoint must not have a query part (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            Map.of(PREFIX + '.' + ENDPOINT, "https://example.com#fragment"),
            singletonList(
                "device code flow: device authorization endpoint must not have a fragment part (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + ENDPOINT,
                "https://example.com",
                PREFIX + '.' + POLL_INTERVAL,
                "PT1S"),
            singletonList(
                "device code flow: poll interval must be greater than or equal to PT5S (rest.auth.oauth2.device-code.poll-interval)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        Map.of(
            PREFIX + '.' + ENDPOINT, "https://example.com/device",
            PREFIX + '.' + POLL_INTERVAL, "PT1M",
            PREFIX + '.' + "min-poll-interval", "PT1M",
            PREFIX + '.' + "ignore-server-poll-interval", "true");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(DeviceCodeConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    DeviceCodeConfig config = smallRyeConfig.getConfigMapping(DeviceCodeConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}

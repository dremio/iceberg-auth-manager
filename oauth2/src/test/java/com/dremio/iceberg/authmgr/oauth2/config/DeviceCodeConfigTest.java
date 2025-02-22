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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.POLL_INTERVAL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.TIMEOUT;
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

class DeviceCodeConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(DeviceCodeConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            DeviceCodeConfig.builder().deviceAuthorizationEndpoint(URI.create("/auth")),
            singletonList(
                "device code flow: device authorization endpoint must not be relative (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com?query")),
            singletonList(
                "device code flow: device authorization endpoint must not have a query part (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com#fragment")),
            singletonList(
                "device code flow: device authorization endpoint must not have a fragment part (rest.auth.oauth2.device-code.endpoint)")),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com"))
                .timeout(Duration.ofSeconds(1)),
            singletonList(
                "device code flow: timeout must be greater than or equal to PT30S (rest.auth.oauth2.device-code.timeout)")),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com"))
                .pollInterval(Duration.ofSeconds(1)),
            singletonList(
                "device code flow: poll interval must be greater than or equal to PT5S (rest.auth.oauth2.device-code.poll-interval)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, DeviceCodeConfig expected, Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      DeviceCodeConfig actual = DeviceCodeConfig.builder().from(properties).build();
      assertThat(actual).isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> DeviceCodeConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            Map.of(ENDPOINT, "https://example.com/device", POLL_INTERVAL, "PT8S", TIMEOUT, "PT45S"),
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(DeviceCodeConfig base, Map<String, String> properties, DeviceCodeConfig expected) {
    DeviceCodeConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            DeviceCodeConfig.builder().build(),
            Map.of(ENDPOINT, "https://example.com/device", POLL_INTERVAL, "PT8S", TIMEOUT, "PT45S"),
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build()),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build(),
            Map.of(),
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build()),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build(),
            Map.of(
                ENDPOINT, "https://example2.com/device", POLL_INTERVAL, "PT9S", TIMEOUT, "PT50S"),
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example2.com/device"))
                .pollInterval(Duration.ofSeconds(9))
                .timeout(Duration.ofSeconds(50))
                .build()),
        Arguments.of(
            DeviceCodeConfig.builder()
                .deviceAuthorizationEndpoint(URI.create("https://example.com/device"))
                .pollInterval(Duration.ofSeconds(8))
                .timeout(Duration.ofSeconds(45))
                .build(),
            Map.of(ENDPOINT, "", POLL_INTERVAL, "", TIMEOUT, ""),
            DeviceCodeConfig.builder().build()));
  }
}

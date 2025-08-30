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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.System.AGENT_NAME;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SystemConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(SystemConfig.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            SystemConfig.builder().agentName(""),
            singletonList("agent name must not be blank (rest.auth.oauth2.system.agent-name)")));
  }

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, SystemConfig expected, Throwable expectedThrowable) {
    if (properties != null && expected != null) {
      SystemConfig actual = SystemConfig.builder().from(properties).build();
      assertThat(actual)
          .usingRecursiveComparison()
          .ignoringFields("clock", "console")
          .isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> SystemConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            Map.of(AGENT_NAME, "my-agent"),
            SystemConfig.builder().agentName("my-agent").build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(SystemConfig base, Map<String, String> properties, SystemConfig expected) {
    SystemConfig merged = base.merge(properties);
    assertThat(merged)
        .usingRecursiveComparison()
        .ignoringFields("clock", "console")
        .isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            SystemConfig.builder().build(),
            Map.of(AGENT_NAME, "my-agent"),
            SystemConfig.builder().agentName("my-agent").build()),
        Arguments.of(
            SystemConfig.builder().agentName("my-agent").build(),
            Map.of(),
            SystemConfig.builder().agentName("my-agent").build()),
        Arguments.of(
            SystemConfig.builder().agentName("my-agent1").build(),
            Map.of(AGENT_NAME, "my-agent2"),
            SystemConfig.builder().agentName("my-agent2").build()),
        Arguments.of(
            SystemConfig.builder().agentName("my-agent2").build(),
            Map.of(AGENT_NAME, ""),
            SystemConfig.builder().build()));
  }
}

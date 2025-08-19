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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.USERNAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.nimbusds.oauth2.sdk.auth.Secret;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ResourceOwnerConfigTest {

  @ParameterizedTest
  @MethodSource
  void testFromProperties(
      Map<String, String> properties, ResourceOwnerConfig expected, Throwable expectedThrowable) {
    if (expectedThrowable == null) {
      ResourceOwnerConfig actual = ResourceOwnerConfig.builder().from(properties).build();
      assertThat(actual)
          .usingRecursiveComparison()
          .ignoringFields("clientSecretProvider")
          .isEqualTo(expected);
    } else {
      Throwable actual = catchThrowable(() -> ResourceOwnerConfig.builder().from(properties));
      assertThat(actual)
          .isInstanceOf(expectedThrowable.getClass())
          .hasMessage(expectedThrowable.getMessage());
    }
  }

  static Stream<Arguments> testFromProperties() {
    return Stream.of(
        Arguments.of(null, null, new NullPointerException("properties must not be null")),
        Arguments.of(
            Map.of(USERNAME, "Alice", PASSWORD, "s3cr3t"),
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build(),
            null));
  }

  @ParameterizedTest
  @MethodSource
  void testMerge(
      ResourceOwnerConfig base, Map<String, String> properties, ResourceOwnerConfig expected) {
    ResourceOwnerConfig merged = base.merge(properties);
    assertThat(merged).isEqualTo(expected);
  }

  static Stream<Arguments> testMerge() {
    return Stream.of(
        Arguments.of(
            ResourceOwnerConfig.builder().build(),
            Map.of(USERNAME, "Alice", PASSWORD, "s3cr3t"),
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build()),
        Arguments.of(
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build(),
            Map.of(),
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build()),
        Arguments.of(
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build(),
            Map.of(USERNAME, "Bob", PASSWORD, "w00t"),
            ResourceOwnerConfig.builder().username("Bob").password(new Secret("w00t")).build()),
        Arguments.of(
            ResourceOwnerConfig.builder().username("Alice").password(new Secret("s3cr3t")).build(),
            Map.of(USERNAME, "", PASSWORD, ""),
            ResourceOwnerConfig.builder().build()));
  }
}

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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class FlowUtilsTest {

  @ParameterizedTest
  @MethodSource
  void scopesAsString(List<String> scopes, String expected) {
    Optional<String> actual = FlowUtils.scopesAsString(scopes);
    assertThat(actual).isEqualTo(Optional.ofNullable(expected));
  }

  public static Stream<Arguments> scopesAsString() {
    return Stream.of(
        Arguments.of(List.of(), null),
        Arguments.of(List.of("scope1"), "scope1"),
        Arguments.of(List.of("scope1", "scope2"), "scope1 scope2"));
  }

  @ParameterizedTest
  @MethodSource
  void scopesAsList(String scopes, List<String> expected) {
    List<String> actual = FlowUtils.scopesAsList(scopes);
    assertThat(actual).isEqualTo(expected);
  }

  public static Stream<Arguments> scopesAsList() {
    return Stream.of(
        Arguments.of(null, List.of()),
        Arguments.of("", List.of()),
        Arguments.of(" ", List.of()),
        Arguments.of("scope1", List.of("scope1")),
        Arguments.of("scope1 scope2", List.of("scope1", "scope2")),
        Arguments.of("  scope1  scope2  ", List.of("scope1", "scope2")));
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 5, 10, 15, 20, 100})
  void testRandomAlphaNumString(int length) {
    String actual = FlowUtils.randomAlphaNumString(length);
    assertThat(actual).hasSize(length).matches("^[a-zA-Z0-9]*$");
  }
}

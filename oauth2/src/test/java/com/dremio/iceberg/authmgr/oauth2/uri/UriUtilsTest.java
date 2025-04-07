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
package com.dremio.iceberg.authmgr.oauth2.uri;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class UriUtilsTest {

  @ParameterizedTest
  @MethodSource
  void testDecodeParameters(String queryString, Map<String, List<String>> expected) {
    Map<String, List<String>> result = UriUtils.decodeParameters(queryString);
    assertThat(result).isEqualTo(expected);
  }

  public static Stream<Arguments> testDecodeParameters() {
    return Stream.of(
        Arguments.of(null, Map.of()),
        Arguments.of("", Map.of()),
        Arguments.of("key1=value1", ImmutableMap.of("key1", List.of("value1"))),
        Arguments.of(
            "key1=value1&key1=value2", ImmutableMap.of("key1", List.of("value1", "value2"))),
        Arguments.of(
            "key1=value1&key2=value2",
            ImmutableMap.of("key1", List.of("value1"), "key2", List.of("value2")),
            Arguments.of("key1=", ImmutableMap.of("key1", List.of(""))),
            Arguments.of(
                "+abcd0123456789.-*_%26%3F%2F%23%40%21%25%5C%3D%E4%BD%A0%E5%A5%BD"
                    + "="
                    + "+abcd0123456789.-*_%26%3F%2F%23%40%21%25%5C%3D%E4%BD%A0%E5%A5%BD",
                ImmutableMap.of(
                    " abcd0123456789.-*_&?/#@!%\\=你好",
                    List.of(" abcd0123456789.-*_&?/#@!%\\=你好")))));
  }

  @ParameterizedTest
  @MethodSource
  void testEncodeParameters(Map<String, List<String>> params, String expected) {
    String result = UriUtils.encodeParameters(params);
    assertThat(result).isEqualTo(expected);
  }

  public static Stream<Arguments> testEncodeParameters() {
    return Stream.of(
        Arguments.of(null, ""),
        Arguments.of(Map.of(), ""),
        Arguments.of(ImmutableMap.of("key1", List.of("value1")), "key1=value1"),
        Arguments.of(
            ImmutableMap.of("key1", List.of("value1", "value2")), "key1=value1&key1=value2"),
        Arguments.of(ImmutableMap.of("key1", List.of("")), "key1="),
        Arguments.of(
            ImmutableMap.of("key1", List.of("value1"), "key2", List.of("value2")),
            "key1=value1&key2=value2"),
        Arguments.of(
            ImmutableMap.of(
                " abcd0123456789.-*_&?/#@!%\\=你好", List.of(" abcd0123456789.-*_&?/#@!%\\=你好")),
            "+abcd0123456789.-*_%26%3F%2F%23%40%21%25%5C%3D%E4%BD%A0%E5%A5%BD"
                + "="
                + "+abcd0123456789.-*_%26%3F%2F%23%40%21%25%5C%3D%E4%BD%A0%E5%A5%BD"));
  }
}

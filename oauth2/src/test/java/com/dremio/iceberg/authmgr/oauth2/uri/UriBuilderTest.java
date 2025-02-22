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
package com.dremio.iceberg.authmgr.oauth2.uri;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class UriBuilderTest {

  @ParameterizedTest
  @CsvSource({
    "http://localhost",
    "http://localhost/",
    "https://user@example:com:8080",
    "https://user@example:com:8080/",
    "http://localhost/foo/bar",
    "http://localhost/foo%20bar%2Fqix/",
    "http://localhost/foo/bar/",
    "http://localhost?param=value#fragment",
    "http://localhost/?param=value#fragment",
    "http://localhost#fragment",
    "http://localhost/#fragment",
    "http://localhost/foo/bar?param=value#fragment",
    "http://localhost/foo/bar/?param=value#fragment",
    "http://localhost/foo/bar/?param=value1&param=value2#fragment",
    "http://localhost/foo?param1=value1%26param2%3Dvalue2#fragment",
    "'http://localhost/.-*@=&~_:!$''(),;=+?param1=.-*_+#fragment'",
  })
  void idempotence(String uri) {
    assertThat(new UriBuilder(URI.create(uri)).build().toString()).isEqualTo(uri);
  }

  @Test
  void invalidInput() {
    assertThatThrownBy(() -> new UriBuilder((String) null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UriBuilder((URI) null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UriBuilder("file:///base"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new UriBuilder(URI.create("http://base/")).path(null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UriBuilder(URI.create("http://base/")).queryParam(null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @ParameterizedTest
  @CsvSource({
    "http://localhost                               ,a/b/c                      ,http://localhost/a/b/c",
    "http://localhost/                              ,a/b/c                      ,http://localhost/a/b/c",
    "http://localhost                               ,/a/b/c                     ,http://localhost/a/b/c",
    "http://localhost/                              ,/a/b/c                     ,http://localhost/a/b/c",
    "http://localhost                               ,a/b/c/                     ,http://localhost/a/b/c/",
    "http://localhost/                              ,a/b/c/                     ,http://localhost/a/b/c/",
    "http://localhost                               ,/a/b/c/                    ,http://localhost/a/b/c/",
    "http://localhost/                              ,/a/b/c/                    ,http://localhost/a/b/c/",
    "http://localhost                               ,a//b//c                    ,http://localhost/a/b/c",
    "http://localhost/                              ,a//b//c                    ,http://localhost/a/b/c",
    "http://localhost                               ,//a//b//c                  ,http://localhost/a/b/c",
    "http://localhost/                              ,//a//b//c                  ,http://localhost/a/b/c",
    "http://localhost                               ,a//b//c//                  ,http://localhost/a/b/c/",
    "http://localhost/                              ,a//b//c//                  ,http://localhost/a/b/c/",
    "http://localhost                               ,//a//b//c//                ,http://localhost/a/b/c/",
    "http://localhost/                              ,//a//b//c//                ,http://localhost/a/b/c/",
    "http://localhost/                              ,' '                        ,http://localhost/%20",
    "http://localhost/                              ,' /'                       ,http://localhost/%20/",
    "http://localhost/                              ,'/ '                       ,http://localhost/%20",
    "http://localhost/                              ,'/ /'                      ,http://localhost/%20/",
    "http://localhost/                              ,'/ / /'                    ,http://localhost/%20/%20/",
    "http://localhost/                              ,' / / / '                  ,http://localhost/%20/%20/%20/%20",
    "http://localhost/                              ,'.-*/@?=/#&?~_:!$''()+,;=' ,http://localhost/.-*/%40%3F%3D/%23%26%3F%7E_%3A%21%24%27%28%29%2B%2C%3B%3D",
    "http://localhost/foo%20bar%2Fqix               ,'.-*/@?=/#&?~_:!$''()+,;=' ,http://localhost/foo%20bar%2Fqix/.-*/%40%3F%3D/%23%26%3F%7E_%3A%21%24%27%28%29%2B%2C%3B%3D",
    "http://localhost/foo%20bar%2Fqix               ,'.-*/@?=/#&?~_:!$''()+,;=' ,http://localhost/foo%20bar%2Fqix/.-*/%40%3F%3D/%23%26%3F%7E_%3A%21%24%27%28%29%2B%2C%3B%3D",
    "http://localhost/foo%20bar%2Fqix?param1=value1 ,'.-*/@?=/#&?~_:!$''()+,;=' ,http://localhost/foo%20bar%2Fqix/.-*/%40%3F%3D/%23%26%3F%7E_%3A%21%24%27%28%29%2B%2C%3B%3D?param1=value1",
  })
  void paths(String base, String path, String expected) {
    assertThat(new UriBuilder(base).path(path).build().toString()).isEqualTo(expected);
  }

  @ParameterizedTest
  @MethodSource
  void queryParameters(String base, Iterable<Entry<String, String>> queryParams, String expected) {
    UriBuilder builder = new UriBuilder(base);
    queryParams.forEach(entry -> builder.queryParam(entry.getKey(), entry.getValue()));
    assertThat(builder.build().toString()).isEqualTo(expected);
  }

  static Stream<Arguments> queryParameters() {
    return Stream.of(
        Arguments.of(
            "http://localhost/foo?param1=value1",
            Maps.newHashMap("a", null).entrySet(),
            "http://localhost/foo?param1=value1"),
        Arguments.of(
            "http://localhost/foo/bar",
            ImmutableMap.of("a", "b").entrySet(),
            "http://localhost/foo/bar?a=b"),
        Arguments.of(
            "http://localhost/foo/bar/",
            ImmutableMap.of("a", "b").entrySet(),
            "http://localhost/foo/bar/?a=b"),
        Arguments.of(
            "http://localhost/foo/bar",
            ImmutableMap.of("a", "b", "c", "d").entrySet(),
            "http://localhost/foo/bar?a=b&c=d"),
        Arguments.of(
            "http://localhost/foo/bar/",
            ImmutableMap.of("a", "b", "c", "d").entrySet(),
            "http://localhost/foo/bar/?a=b&c=d"),
        Arguments.of(
            "http://localhost",
            ImmutableMap.of("param1", "value1&param2=value2").entrySet(),
            "http://localhost?param1=value1%26param2%3Dvalue2"),
        Arguments.of(
            "http://localhost/foo?param1=value1",
            ImmutableMap.of("param1", "value2").entrySet(),
            "http://localhost/foo?param1=value1&param1=value2"),
        Arguments.of(
            "http://localhost/foo?param1=value1",
            List.of(Map.entry("param1", "value2"), Map.entry("param1", "value3")),
            "http://localhost/foo?param1=value1&param1=value2&param1=value3"),
        Arguments.of(
            "http://localhost/foo?param1=value1",
            List.of(Map.entry("param1", ".-*_ ")),
            "http://localhost/foo?param1=value1&param1=.-*_+"),
        Arguments.of(
            "http://localhost/foo?param1=value1%26param2%3Dvalue2#fragment",
            ImmutableMap.of("param2", "&? /#").entrySet(),
            "http://localhost/foo?param1=value1%26param2%3Dvalue2&param2=%26%3F+%2F%23#fragment"));
  }

  @Test
  void clearPath() {
    assertThat(
            new UriBuilder("http://localhost/foo/bar?a=b#fragment")
                .path("a/b/c")
                .clearPath()
                .build()
                .toString())
        .isEqualTo("http://localhost?a=b#fragment");
    assertThat(
            new UriBuilder("http://localhost/foo/bar?a=b#fragment")
                .path("a/b/c")
                .clearPath()
                .path("/")
                .build()
                .toString())
        .isEqualTo("http://localhost/?a=b#fragment");
  }

  @Test
  void clearQueryParams() {
    assertThat(
            new UriBuilder("http://localhost/foo/bar?a=b#fragment")
                .queryParam("c", "d")
                .clearQueryParams()
                .build()
                .toString())
        .isEqualTo("http://localhost/foo/bar#fragment");
    assertThat(
            new UriBuilder("http://localhost/foo/bar?a=b#fragment")
                .queryParam("c", "d")
                .clearQueryParams()
                .queryParam("e", "f")
                .build()
                .toString())
        .isEqualTo("http://localhost/foo/bar?e=f#fragment");
  }
}

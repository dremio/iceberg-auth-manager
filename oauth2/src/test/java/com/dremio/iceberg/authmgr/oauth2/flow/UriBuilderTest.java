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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import org.junit.jupiter.api.Test;

class UriBuilderTest {

  @Test
  void simple() {
    assertThat(new UriBuilder("http://localhost").build().toString()).isEqualTo("http://localhost");
    assertThat(new UriBuilder("http://localhost/").build().toString())
        .isEqualTo("http://localhost/");
    assertThat(new UriBuilder("http://localhost/foo/bar").build().toString())
        .isEqualTo("http://localhost/foo/bar");
    assertThat(new UriBuilder("http://localhost/foo/bar/").build().toString())
        .isEqualTo("http://localhost/foo/bar/");
    assertThat(new UriBuilder("http://localhost/foo/bar?param=value#fragment").build().toString())
        .isEqualTo("http://localhost/foo/bar");
    assertThat(new UriBuilder("http://localhost/foo/bar/?param=value#fragment").build().toString())
        .isEqualTo("http://localhost/foo/bar/");
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void parameterValidation() {
    assertThatThrownBy(() -> new UriBuilder((String) null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UriBuilder((URI) null)).isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new UriBuilder(URI.create("http://base/")).path(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void addMissingSlash() {
    assertThat(new UriBuilder(URI.create("http://localhost")).path("foo").build().toString())
        .isEqualTo("http://localhost/foo");
    assertThat(
            new UriBuilder(URI.create("http://localhost"))
                .path("foo")
                .path("bar")
                .build()
                .toString())
        .isEqualTo("http://localhost/foo/bar");
  }

  @Test
  void pathEncoding() {
    assertThat(
            new UriBuilder(URI.create("http://localhost/foo/bar/"))
                .path("some spaces in here")
                .build()
                .toString())
        .isEqualTo("http://localhost/foo/bar/some%20spaces%20in%20here");
  }

  @Test
  void slashesInPaths() {
    URI expected = URI.create("http://localhost/a/b/c");
    assertThat(new UriBuilder(URI.create("http://localhost")).path("a/b/c").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost/")).path("a/b/c").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost")).path("/a/b/c").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost/")).path("/a/b/c").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost")).path("a/b/c/").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost/")).path("a/b/c/").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost")).path("/a/b/c/").build())
        .isEqualTo(expected);
    assertThat(new UriBuilder(URI.create("http://localhost/")).path("/a/b/c/").build())
        .isEqualTo(expected);
  }

  @Test
  void queryParameters() {
    UriBuilder builder = new UriBuilder(URI.create("http://localhost/foo/bar/"));

    builder = builder.queryParam("a", "b");
    assertThat(builder.build().toString()).isEqualTo("http://localhost/foo/bar/?a=b");

    builder = builder.queryParam("c", "d");
    assertThat(builder.build().toString()).isEqualTo("http://localhost/foo/bar/?a=b&c=d");

    builder = builder.queryParam("e", "f&? /");
    assertThat(builder.build().toString())
        .isEqualTo("http://localhost/foo/bar/?a=b&c=d&e=f%26%3F%20%2F");

    builder = builder.queryParam("c", "d-more");
    assertThat(builder.build().toString())
        .isEqualTo("http://localhost/foo/bar/?a=b&c=d&e=f%26%3F%20%2F&c=d-more");
  }
}

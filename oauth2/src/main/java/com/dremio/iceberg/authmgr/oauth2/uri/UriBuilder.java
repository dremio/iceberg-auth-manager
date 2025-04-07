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

import static java.util.Objects.requireNonNull;

import jakarta.annotation.Nullable;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.iceberg.exceptions.RESTException;

/**
 * Simple URI builder that supports manipulating path segments and query parameters from a base URI.
 * It only supports HTTP and HTTPS schemes.
 */
public class UriBuilder {

  private final URI baseUri;
  private final StringBuilder encodedPath = new StringBuilder();
  private final Map<String, List<String>> queryParams = new LinkedHashMap<>();

  public UriBuilder(String baseUri) {
    this(URI.create(baseUri));
  }

  public UriBuilder(URI baseUri) {
    if (baseUri.getScheme() == null
        || baseUri.getScheme().isEmpty()
        || !baseUri.getScheme().equals("http") && !baseUri.getScheme().equals("https")) {
      throw new IllegalArgumentException("baseUri must have an HTTP or HTTPS scheme");
    }
    this.baseUri = requireNonNull(baseUri, "baseUri is null");
    if (baseUri.getRawPath() != null) {
      encodedPath.append(baseUri.getRawPath());
    }
    if (baseUri.getRawQuery() != null) {
      queryParams.putAll(UriUtils.decodeParameters(baseUri.getRawQuery()));
    }
  }

  public UriBuilder clearPath() {
    encodedPath.setLength(0);
    return this;
  }

  public UriBuilder clearQueryParams() {
    queryParams.clear();
    return this;
  }

  /**
   * Adds one or more path segments to the URI. Path segments are separated by a single '/'. Paths
   * should NOT be URL encoded, as this method will handle that. If the path is empty, it will be
   * ignored.
   *
   * <p>Note: if the path contains a '/' it will be treated as a path segment separator. For
   * example, path("foo/bar") will be treated as two segments: "foo" and "bar". It is not possible
   * to add a path segment that contains a '/'.
   */
  public UriBuilder path(String unencodedPath) {
    if (unencodedPath == null) {
      throw new NullPointerException("path is null");
    }
    if (!unencodedPath.isEmpty()) {
      if (encodedPath.length() == 0 || encodedPath.charAt(encodedPath.length() - 1) != '/') {
        encodedPath.append('/');
      }
      StringBuilder pathSegment = new StringBuilder();
      for (int i = 0; i < unencodedPath.length(); i++) {
        char c = unencodedPath.charAt(i);
        if (c == '/') {
          if (pathSegment.length() > 0) {
            encodedPath.append(encodePathSegment(pathSegment.toString()));
            pathSegment.setLength(0);
            encodedPath.append('/');
          }
        } else {
          pathSegment.append(c);
        }
      }
      encodedPath.append(encodePathSegment(pathSegment.toString()));
    }
    return this;
  }

  /**
   * Adds a query parameter to the URI. If the value is null, the parameter is ignored. The
   * parameter name and value should NOT be URL encoded, as this method will handle that.
   *
   * <p>If a parameter with same name already exists, the value will be added to the list of values
   * for that parameter.
   */
  public UriBuilder queryParam(String unencodedName, @Nullable String unencodedValue) {
    if (unencodedName == null) {
      throw new NullPointerException("name is null");
    }
    if (unencodedValue != null) {
      queryParams.merge(
          unencodedName,
          List.of(unencodedValue),
          (l1, l2) -> Stream.concat(l1.stream(), l2.stream()).collect(Collectors.toList()));
    }
    return this;
  }

  public URI build() throws RESTException {
    StringBuilder uriBuilder = new StringBuilder();
    uriBuilder.append(baseUri.getScheme()).append("://");
    if (baseUri.getRawAuthority() != null) {
      uriBuilder.append(baseUri.getRawAuthority());
    }
    uriBuilder.append(encodedPath);
    if (!queryParams.isEmpty()) {
      uriBuilder.append('?');
      uriBuilder.append(UriUtils.encodeParameters(queryParams));
    }
    if (baseUri.getRawFragment() != null && !baseUri.getRawFragment().isEmpty()) {
      uriBuilder.append('#').append(baseUri.getRawFragment());
    }
    return URI.create(uriBuilder.toString());
  }

  /**
   * Encodes a path segment using "percent" encoding.
   *
   * <p>URLEncoder is tailored for query strings and form parameters. It encodes spaces as '+',
   * which conflicts with a real '+' sign. We need to replace '+' with '%20' to ensure the path
   * segment remains correct.
   *
   * <p>Also, URLEncoder encodes a lot more than necessary for a path segment, but this is the
   * safest approach, using only standard Java libraries, to ensure that the path segment is valid.
   */
  private static String encodePathSegment(String pathSegment) {
    return URLEncoder.encode(pathSegment, StandardCharsets.UTF_8).replace("+", "%20");
  }
}

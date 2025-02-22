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

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import org.apache.iceberg.exceptions.RESTException;

/**
 * Construct a URI from base and paths. Adds query parameters, supports templates and handles url
 * encoding of path.
 */
public class UriBuilder {

  private static final Pattern BACKSLASH_PATTERN = Pattern.compile("\\+");

  private final URI baseUri;
  private final StringBuilder uri = new StringBuilder();
  private final StringBuilder query = new StringBuilder();

  public UriBuilder(String baseUri) {
    this(URI.create(requireNonNull(baseUri, "baseUri is null")));
  }

  public UriBuilder(URI baseUri) {
    this.baseUri = requireNonNull(baseUri, "baseUri is null").resolve(baseUri.getPath());
  }

  public UriBuilder path(String path) {
    String trimmedPath = path.trim();
    if (trimmedPath.isEmpty()) {
      throw new IllegalArgumentException("Path must be of length greater than 0");
    }
    if (uri.length() > 0 && !trimmedPath.startsWith("/")) {
      uri.append('/');
    }
    uri.append(trimmedPath);
    return this;
  }

  public UriBuilder queryParam(String name, String value) {
    if (value == null) {
      return this;
    }
    if (query.length() > 0) {
      query.append('&');
    }
    query.append(encode(name.trim())).append('=').append(encode(value.trim()));
    return this;
  }

  public URI build() throws RESTException {
    StringBuilder uriBuilder = new StringBuilder();
    uriBuilder.append(baseUri);

    if (uri.length() > 0) {

      if ('/' != uriBuilder.charAt(uriBuilder.length() - 1)) {
        uriBuilder.append('/');
      }

      StringBuilder pathElement = new StringBuilder();
      int l = uri.length();
      for (int i = 0; i < l; i++) {
        char c = uri.charAt(i);
        if (c == '/') {
          if (pathElement.length() > 0) {
            uriBuilder.append(encode(pathElement.toString()));
            pathElement.setLength(0);
            uriBuilder.append('/');
          }
          if ('/' != uriBuilder.charAt(uriBuilder.length() - 1)) {
            uriBuilder.append('/');
          }
        } else {
          pathElement.append(c);
        }
      }

      uriBuilder.append(encode(pathElement.toString()));

      // clean off the last / that the joiner added
      if ('/' == uriBuilder.charAt(uriBuilder.length() - 1)) {
        return URI.create(uriBuilder.subSequence(0, uriBuilder.length() - 1).toString());
      }
    }

    if (query.length() > 0) {
      uriBuilder.append("?");
      uriBuilder.append(query);
    }

    return URI.create(uriBuilder.toString());
  }

  private static String encode(String s) {
    // URLEncoder encodes space ' ' to + according to how encoding forms should work. When
    // encoding URLs %20 should be used instead.
    return BACKSLASH_PATTERN
        .matcher(URLEncoder.encode(s, StandardCharsets.UTF_8))
        .replaceAll("%20");
  }
}

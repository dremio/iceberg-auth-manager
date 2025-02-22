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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UriUtils {

  /**
   * Decodes a string in {@code application/x-www-form-urlencoded} format into a map of parameters.
   */
  public static Map<String, List<String>> decodeParameters(String query) {
    if (query == null || query.isEmpty()) {
      return Map.of();
    }
    Map<String, List<String>> params = new LinkedHashMap<>();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
      int idx = pair.indexOf("=");
      String name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
      String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
      params.merge(
          name,
          List.of(value),
          (l1, l2) -> Stream.concat(l1.stream(), l2.stream()).collect(Collectors.toList()));
    }
    return Map.copyOf(params);
  }

  /**
   * Encodes the given parameters into a string in {@code application/x-www-form-urlencoded} format.
   * The map entries should NOT be URL-encoded.
   */
  public static String encodeParameters(Map<String, List<String>> params) {
    if (params == null || params.isEmpty()) {
      return "";
    }
    StringBuilder query = new StringBuilder();
    for (Map.Entry<String, List<String>> entry : params.entrySet()) {
      for (String value : entry.getValue()) {
        if (query.length() > 0) {
          query.append('&');
        }
        query
            .append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
            .append('=')
            .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
      }
    }
    return query.toString();
  }
}

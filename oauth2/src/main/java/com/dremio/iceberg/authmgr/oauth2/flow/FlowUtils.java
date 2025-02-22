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

import jakarta.annotation.Nullable;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

public final class FlowUtils {

  public static final String OAUTH2_AGENT_TITLE = "======== Authentication Required ========";
  public static final String OAUTH2_AGENT_OPEN_URL = "Please open the following URL to continue:";

  private static final Random RANDOM = new SecureRandom();

  private FlowUtils() {}

  public static Optional<String> scopesAsString(List<String> scopes) {
    return scopes.stream().reduce((a, b) -> a + " " + b);
  }

  public static List<String> scopesAsList(@Nullable String scopes) {
    return scopes == null || scopes.isBlank() ? List.of() : List.of(scopes.trim().split(" +"));
  }

  public static Map<String, String> parseQueryString(String query) {
    if (query == null) {
      throw new IllegalArgumentException("Missing query string");
    }
    Map<String, String> params = new HashMap<>();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
      int idx = pair.indexOf("=");
      String name;
      String value;
      name = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
      value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
      params.put(name, value);
    }
    return params;
  }

  public static String randomAlphaNumString(int length) {
    return RANDOM
        .ints('0', 'z' + 1)
        .filter(i -> (i <= '9') || (i >= 'A' && i <= 'Z') || (i >= 'a'))
        .limit(length)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString();
  }

  public static String getContextPath(String agentName) {
    return '/' + agentName + "/auth";
  }

  public static String getMsgPrefix(String agentName) {
    return '[' + agentName + "] ";
  }
}

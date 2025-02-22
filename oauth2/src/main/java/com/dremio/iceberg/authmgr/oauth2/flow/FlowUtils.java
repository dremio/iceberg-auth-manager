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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
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

  public static String randomAlphaNumString(int length) {
    return RANDOM
        .ints('0', 'z' + 1)
        .filter(i -> (i <= '9') || (i >= 'A' && i <= 'Z') || (i >= 'a'))
        .limit(length)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString();
  }

  /**
   * Generates a code verifier for PKCE.
   *
   * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7636#section-4.1">RFC 7636 Section
   * 4.1</a>
   */
  public static String generateCodeVerifier() {
    byte[] codeVerifier = new byte[32];
    RANDOM.nextBytes(codeVerifier);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
  }

  /**
   * Generates a code challenge for PKCE, using the S256 method.
   *
   * <p>See <a href="https://datatracker.ietf.org/doc/html/rfc7636#section-4.2">RFC 7636 Section
   * 4.2</a>
   */
  public static String generateS256CodeChallenge(String codeVerifier) {
    byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    messageDigest.update(bytes, 0, bytes.length);
    byte[] digest = messageDigest.digest();
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  public static String getContextPath(String agentName) {
    return '/' + agentName + "/auth";
  }

  public static String getMsgPrefix(String agentName) {
    return '[' + agentName + "] ";
  }
}

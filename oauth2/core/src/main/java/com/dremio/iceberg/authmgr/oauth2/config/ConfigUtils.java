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

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class ConfigUtils {

  public static final List<GrantType> SUPPORTED_INITIAL_GRANT_TYPES =
      List.of(
          GrantType.CLIENT_CREDENTIALS,
          GrantType.PASSWORD,
          GrantType.AUTHORIZATION_CODE,
          GrantType.DEVICE_CODE,
          GrantType.TOKEN_EXCHANGE);

  public static final List<ClientAuthenticationMethod> SUPPORTED_CLIENT_AUTH_METHODS =
      List.of(
          ClientAuthenticationMethod.NONE,
          ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
          ClientAuthenticationMethod.CLIENT_SECRET_POST,
          ClientAuthenticationMethod.CLIENT_SECRET_JWT,
          ClientAuthenticationMethod.PRIVATE_KEY_JWT);

  public static final List<CodeChallengeMethod> SUPPORTED_CODE_CHALLENGE_METHODS =
      List.of(CodeChallengeMethod.PLAIN, CodeChallengeMethod.S256);

  public static boolean requiresClientSecret(ClientAuthenticationMethod method) {
    return method.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        || method.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        || method.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
  }

  public static boolean requiresJwsAlgorithm(ClientAuthenticationMethod method) {
    return method.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        || method.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
  }

  public static boolean requiresUserInteraction(GrantType grantType) {
    return grantType.equals(GrantType.AUTHORIZATION_CODE)
        || grantType.equals(GrantType.DEVICE_CODE);
  }

  public static List<String> parseCommaSeparatedList(String text) {
    if (text == null || text.isBlank()) {
      return List.of();
    }
    String[] parts = text.trim().split(",");
    return Stream.of(parts).map(String::trim).collect(Collectors.toList());
  }

  public static Map<String, String> prefixedMap(Map<String, String> properties, String prefix) {
    return properties.entrySet().stream()
        .map(e -> Map.entry(prefix + '.' + e.getKey(), e.getValue()))
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  private ConfigUtils() {}
}

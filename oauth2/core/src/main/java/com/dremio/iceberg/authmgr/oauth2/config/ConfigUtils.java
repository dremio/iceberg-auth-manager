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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import java.net.URI;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class ConfigUtils {

  private ConfigUtils() {}

  public static GrantType parseGrantType(String grantType) {
    try {
      return GrantType.parse(grantType);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to parse grant type: " + grantType, e);
    }
  }

  public static TokenTypeURI parseTokenTypeURI(String uri) {
    try {
      return TokenTypeURI.parse(uri);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to parse token type URI: " + uri, e);
    }
  }

  public static List<Audience> parseAudienceList(String audience) {
    return parseSpaceSeparatedList(audience, Audience::new);
  }

  public static List<URI> parseUriList(String uris) {
    return parseSpaceSeparatedList(uris, URI::create);
  }

  public static List<String> parseSpaceSeparatedList(String text) {
    return parseList(text, " +", Function.identity());
  }

  public static List<String> parseCommaSeparatedList(String text) {
    return parseList(text, ",", Function.identity());
  }

  public static <T> List<T> parseSpaceSeparatedList(String text, Function<String, T> mapper) {
    return parseList(text, " +", mapper);
  }

  public static <T> List<T> parseCommaSeparatedList(String text, Function<String, T> mapper) {
    return parseList(text, ",", mapper);
  }

  public static <T> List<T> parseList(String text, String separator, Function<String, T> mapper) {
    if (text == null || text.isBlank()) {
      return List.of();
    }
    String[] parts = text.trim().split(separator);
    return Stream.of(parts).map(String::trim).map(mapper).collect(Collectors.toList());
  }

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
}

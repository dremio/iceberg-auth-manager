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
package com.dremio.iceberg.authmgr.oauth2.compat;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.iceberg.util.PropertyUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class LegacyPropertiesMigrator {

  private static final Logger LOGGER = LoggerFactory.getLogger(LegacyPropertiesMigrator.class);

  /**
   * Migrates legacy Iceberg OAuth2 properties to the new OAuth2 properties, and logs warnings when
   * legacy properties are detected. Returns a copy of the input map containing only the migrated
   * properties starting with the `rest.auth.oauth2.` prefix.
   */
  public static Map<String, String> migrate(Map<String, String> properties) {
    Map<String, String> migrated = new HashMap<>();
    for (Entry<String, String> entry : properties.entrySet()) {
      switch (entry.getKey()) {
        case org.apache.iceberg.rest.auth.OAuth2Properties.CREDENTIAL:
          warnOnIcebergOAuth2Property(
              entry.getKey(),
              OAuth2Properties.Basic.CLIENT_ID,
              OAuth2Properties.Basic.CLIENT_SECRET);
          String[] parts = entry.getValue().split(":");
          switch (parts.length) {
            case 2:
              migrated.put(OAuth2Properties.Basic.CLIENT_ID, parts[0]);
              migrated.put(OAuth2Properties.Basic.CLIENT_SECRET, parts[1]);
              break;
            case 1:
              // Iceberg dialect: client secret without client id
              migrated.put(OAuth2Properties.Basic.CLIENT_SECRET, parts[0]);
              break;
            default:
              throw new IllegalArgumentException("Invalid credential: " + entry.getValue());
          }
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.TOKEN:
          warnOnIcebergOAuth2Property(entry.getKey(), OAuth2Properties.Basic.TOKEN);
          migrated.put(OAuth2Properties.Basic.TOKEN, entry.getValue());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.TOKEN_EXPIRES_IN_MS:
          warnOnIcebergOAuth2Property(
              entry.getKey(), OAuth2Properties.TokenRefresh.ACCESS_TOKEN_LIFESPAN);
          Duration duration =
              Duration.ofMillis(
                  PropertyUtil.propertyAsLong(
                      properties,
                      org.apache.iceberg.rest.auth.OAuth2Properties.TOKEN_EXPIRES_IN_MS,
                      org.apache.iceberg.rest.auth.OAuth2Properties.TOKEN_EXPIRES_IN_MS_DEFAULT));
          migrated.put(
              OAuth2Properties.TokenRefresh.DEFAULT_ACCESS_TOKEN_LIFESPAN, duration.toString());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.TOKEN_REFRESH_ENABLED:
          warnOnIcebergOAuth2Property(entry.getKey(), OAuth2Properties.TokenRefresh.ENABLED);
          migrated.put(
              OAuth2Properties.TokenRefresh.ENABLED,
              String.valueOf(Boolean.parseBoolean(entry.getValue())));
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.OAUTH2_SERVER_URI:
          warnOnIcebergOAuth2Property(
              entry.getKey(),
              OAuth2Properties.Basic.ISSUER_URL,
              OAuth2Properties.Basic.TOKEN_ENDPOINT);
          migrated.put(OAuth2Properties.Basic.TOKEN_ENDPOINT, entry.getValue());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE:
          warnOnIcebergOAuth2Property(entry.getKey(), OAuth2Properties.Basic.SCOPE);
          migrated.put(OAuth2Properties.Basic.SCOPE, entry.getValue());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.AUDIENCE:
          warnOnIcebergOAuth2Property(entry.getKey(), OAuth2Properties.TokenExchange.AUDIENCE);
          migrated.put(OAuth2Properties.TokenExchange.AUDIENCE, entry.getValue());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.RESOURCE:
          warnOnIcebergOAuth2Property(entry.getKey(), OAuth2Properties.TokenExchange.RESOURCE);
          migrated.put(OAuth2Properties.TokenExchange.RESOURCE, entry.getValue());
          break;
        case org.apache.iceberg.rest.auth.OAuth2Properties.ACCESS_TOKEN_TYPE:
        case org.apache.iceberg.rest.auth.OAuth2Properties.ID_TOKEN_TYPE:
        case org.apache.iceberg.rest.auth.OAuth2Properties.SAML1_TOKEN_TYPE:
        case org.apache.iceberg.rest.auth.OAuth2Properties.SAML2_TOKEN_TYPE:
        case org.apache.iceberg.rest.auth.OAuth2Properties.JWT_TOKEN_TYPE:
          LOGGER.warn(
              "Ignoring legacy property '{}': vended token exchange is not supported.",
              entry.getKey());
          break;
        default:
          if (entry.getKey().startsWith(OAuth2Properties.PREFIX)) {
            migrated.put(entry.getKey(), entry.getValue());
          }
      }
    }
    return Map.copyOf(migrated);
  }

  private static void warnOnIcebergOAuth2Property(
      String icebergOption, String... authManagerOptions) {
    // FIXME avoid spamming the logs if the same property appears multiple times
    LOGGER.warn(
        "Detected legacy property '{}', please use option{} {} instead.",
        icebergOption,
        authManagerOptions.length > 1 ? "s" : "",
        Stream.of(authManagerOptions).collect(Collectors.joining("' and '", "'", "'")));
  }
}

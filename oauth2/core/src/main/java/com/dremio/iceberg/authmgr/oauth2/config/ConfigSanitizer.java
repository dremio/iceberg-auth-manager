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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ConfigSanitizer {

  public static final Set<String> CONTEXT_DENY_LIST = Set.of();

  public static final Set<String> TABLE_DENY_LIST =
      Set.of(
          OAuth2Properties.Basic.CLIENT_ID,
          OAuth2Properties.Basic.CLIENT_SECRET,
          OAuth2Properties.ResourceOwner.USERNAME,
          OAuth2Properties.ResourceOwner.PASSWORD,
          OAuth2Properties.ClientAssertion.ALGORITHM,
          OAuth2Properties.ClientAssertion.PRIVATE_KEY);

  private static final Logger LOGGER = LoggerFactory.getLogger(ConfigSanitizer.class);

  private final BiConsumer<String, String> logConsumer;

  public ConfigSanitizer() {
    this(LOGGER);
  }

  private ConfigSanitizer(Logger logger) {
    this(logger::warn);
  }

  ConfigSanitizer(BiConsumer<String, String> logConsumer) {
    this.logConsumer = logConsumer;
  }

  /** Sanitizes context properties received from the catalog's session context. */
  public Map<String, String> sanitizeContextProperties(Map<String, String> properties) {
    return sanitizeProperties(
        properties,
        CONTEXT_DENY_LIST,
        "Ignoring property '{}': this property is not allowed in a session context.");
  }

  /** Sanitizes table properties received from the server. */
  public Map<String, String> sanitizeTableProperties(Map<String, String> properties) {
    return sanitizeProperties(
        properties,
        TABLE_DENY_LIST,
        "Ignoring property '{}': this property is not allowed to be vended by catalog servers.");
  }

  private Map<String, String> sanitizeProperties(
      Map<String, String> properties, Set<String> denyList, String message) {
    properties = new HashMap<>(properties);
    for (Iterator<String> iterator = properties.keySet().iterator(); iterator.hasNext(); ) {
      String key = iterator.next();
      if (denyList.contains(key)) {
        logConsumer.accept(message, key);
        iterator.remove();
      }
    }
    return properties;
  }
}

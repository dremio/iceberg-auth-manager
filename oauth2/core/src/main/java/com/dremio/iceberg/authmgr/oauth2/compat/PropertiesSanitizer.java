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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PropertiesSanitizer {

  private static final Set<String> CONTEXT_DENY_LIST = Set.of(OAuth2Properties.Basic.DIALECT);

  private static final Set<String> TABLE_DENY_LIST =
      Set.of(
          OAuth2Properties.Basic.CLIENT_ID,
          OAuth2Properties.Basic.CLIENT_SECRET,
          OAuth2Properties.Basic.DIALECT,
          OAuth2Properties.ResourceOwner.USERNAME,
          OAuth2Properties.ResourceOwner.PASSWORD,
          OAuth2Properties.Impersonation.CLIENT_ID,
          OAuth2Properties.Impersonation.CLIENT_SECRET,
          OAuth2Properties.TokenExchange.SUBJECT_TOKEN,
          OAuth2Properties.TokenExchange.ACTOR_TOKEN,
          OAuth2Properties.ClientAssertion.ALGORITHM,
          OAuth2Properties.ClientAssertion.PRIVATE_KEY,
          OAuth2Properties.ImpersonationClientAssertion.ALGORITHM,
          OAuth2Properties.ImpersonationClientAssertion.PRIVATE_KEY);

  private static final Logger LOGGER = LoggerFactory.getLogger(PropertiesSanitizer.class);

  /** Sanitizes context properties received from the catalog's session context. */
  public static Map<String, String> sanitizeContextProperties(Map<String, String> properties) {
    properties = new HashMap<>(properties);
    for (Iterator<String> iterator = properties.keySet().iterator(); iterator.hasNext(); ) {
      String key = iterator.next();
      if (CONTEXT_DENY_LIST.contains(key)) {
        LOGGER.warn(
            "Ignoring property '{}': this property is not allowed in a session context.", key);
        iterator.remove();
      }
    }
    return properties;
  }

  /** Sanitizes table properties received from the server. */
  public static Map<String, String> sanitizeTableProperties(Map<String, String> properties) {
    properties = new HashMap<>(properties);
    for (Iterator<String> iterator = properties.keySet().iterator(); iterator.hasNext(); ) {
      String key = iterator.next();
      if (TABLE_DENY_LIST.contains(key)) {
        LOGGER.warn(
            "Ignoring property '{}': this property is not allowed to be vended by catalog servers.",
            key);
        iterator.remove();
      }
      if (key.equals(OAuth2Properties.Basic.TOKEN)) {
        LOGGER.warn(
            "Detected property '{}' in a server response. "
                + "Vending OAuth2 tokens will be disallowed in a future release; "
                + "catalog servers should vend OAuth2 scopes instead.",
            key);
      }
    }
    return properties;
  }
}

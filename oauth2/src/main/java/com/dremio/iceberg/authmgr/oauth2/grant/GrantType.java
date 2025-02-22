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
package com.dremio.iceberg.authmgr.oauth2.grant;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

public enum GrantType {
  CLIENT_CREDENTIALS(GrantCanonicalNames.CLIENT_CREDENTIALS, GrantCommonNames.CLIENT_CREDENTIALS),
  PASSWORD(GrantCanonicalNames.PASSWORD, GrantCommonNames.PASSWORD),
  AUTHORIZATION_CODE(GrantCanonicalNames.AUTHORIZATION_CODE, GrantCommonNames.AUTHORIZATION_CODE),
  DEVICE_CODE(GrantCanonicalNames.DEVICE_CODE, GrantCommonNames.DEVICE_CODE),
  REFRESH_TOKEN(GrantCanonicalNames.REFRESH_TOKEN, GrantCommonNames.REFRESH_TOKEN),
  TOKEN_EXCHANGE(GrantCanonicalNames.TOKEN_EXCHANGE, GrantCommonNames.TOKEN_EXCHANGE);

  private final String canonicalName;
  private final String commonName;

  GrantType(String canonicalName, String commonName) {
    this.canonicalName = canonicalName;
    this.commonName = commonName;
  }

  @JsonValue
  public String getCanonicalName() {
    return canonicalName;
  }

  public String getCommonName() {
    return commonName;
  }

  public static GrantType fromConfigName(String name) {
    for (GrantType grantType : values()) {
      if (grantType.commonName.equals(name.toLowerCase(Locale.ROOT))
          || grantType.canonicalName.equals(name)) {
        return grantType;
      }
    }
    throw new IllegalArgumentException("Unknown grant type: " + name);
  }

  public boolean requiresUserInteraction() {
    return this == AUTHORIZATION_CODE || this == DEVICE_CODE;
  }

  public boolean isInitial() {
    return this != REFRESH_TOKEN;
  }
}

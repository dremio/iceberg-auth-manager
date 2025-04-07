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

import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import java.util.Locale;

public enum PkceTransformation {
  S256("S256") {
    @Override
    public String transform(String codeVerifier) {
      return FlowUtils.generateS256CodeChallenge(codeVerifier);
    }
  },
  PLAIN("plain") {
    @Override
    public String transform(String codeVerifier) {
      return codeVerifier;
    }
  };

  private final String canonicalName;

  PkceTransformation(String canonicalName) {
    this.canonicalName = canonicalName;
  }

  public abstract String transform(String codeVerifier);

  public String getCanonicalName() {
    return canonicalName;
  }

  public static PkceTransformation fromConfigName(String name) {
    try {
      return valueOf(name.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException ignore) {
      throw new IllegalArgumentException("Unknown OAuth2 dialect: " + name);
    }
  }
}

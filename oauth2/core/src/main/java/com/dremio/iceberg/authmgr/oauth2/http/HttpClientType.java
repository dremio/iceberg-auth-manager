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
package com.dremio.iceberg.authmgr.oauth2.http;

import com.dremio.iceberg.authmgr.oauth2.config.HttpConfig;
import com.google.errorprone.annotations.MustBeClosed;

public enum HttpClientType {
  DEFAULT {
    @Override
    public HttpClient newHttpClient(HttpConfig config) {
      return HttpClient.DEFAULT;
    }
  },

  APACHE {
    @Override
    public HttpClient newHttpClient(HttpConfig config) {
      return new ApacheHttpClient(config);
    }
  },
  ;

  /** Creates an HTTP client based on the provided configuration. */
  @MustBeClosed
  public abstract HttpClient newHttpClient(HttpConfig config);

  public static HttpClientType fromString(String value) {
    for (HttpClientType type : values()) {
      if (type.name().equalsIgnoreCase(value)) {
        return type;
      }
    }
    throw new IllegalArgumentException("Unsupported HTTP client type: " + value);
  }
}

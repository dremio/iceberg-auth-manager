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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.google.errorprone.annotations.MustBeClosed;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import java.io.IOException;

/**
 * A simple HTTP client interface that extends the Nimbus {@link HTTPRequestSender} and {@link
 * AutoCloseable} interfaces.
 */
public interface HttpClient extends HTTPRequestSender, AutoCloseable {

  /**
   * The default HTTP client implementation that uses the built-in HTTP request sender from the
   * Nimbus library.
   *
   * <p>This sender is based on URLConnection and does not support advanced features like connection
   * pooling or custom timeouts.
   */
  HttpClient DEFAULT =
      new HttpClient() {

        @Override
        public HTTPResponse send(ReadOnlyHTTPRequest request) throws IOException {
          return ((HTTPRequest) request).send();
        }

        @Override
        public void close() {}
      };

  /** Creates an HTTP client based on the provided OAuth2 configuration. */
  @MustBeClosed
  static HttpClient create(OAuth2Config config) {
    HttpClientType httpClientType = config.getSystemConfig().getHttpClientType();
    switch (httpClientType) {
      case DEFAULT:
        return DEFAULT;
      case APACHE:
        throw new UnsupportedOperationException("Apache HttpClient not implemented yet");
      default:
        throw new IllegalArgumentException("Unsupported HTTP client type: " + httpClientType);
    }
  }

  @Override
  void close();
}

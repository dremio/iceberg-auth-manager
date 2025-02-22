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
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import org.immutables.value.Value.Redacted;

/**
 * Common interface for requests using where the client may authenticate with request body
 * parameters.
 *
 * @see AuthorizationCodeTokenRequest
 * @see DeviceAccessTokenRequest
 * @see DeviceAuthorizationRequest
 * @see PasswordTokenRequest
 * @see RefreshTokenRequest
 * @see TokenExchangeRequest
 */
public interface ClientRequest extends PostFormRequest {

  /**
   * The client identifier as described in href="<a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">Section 2.2</a>.
   */
  @Nullable
  String getClientId();

  /**
   * The client password as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">Section 2.3.1</a>.
   */
  @Nullable
  @Redacted
  String getClientSecret();

  @Override
  default Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>();
    if (getClientId() != null) {
      data.put("client_id", getClientId());
    }
    if (getClientSecret() != null) {
      data.put("client_secret", getClientSecret());
    }
    return Map.copyOf(data);
  }

  interface Builder<T, B extends Builder<T, B>> {
    @CanIgnoreReturnValue
    B clientId(String clientId);

    @CanIgnoreReturnValue
    B clientSecret(String clientSecret);
  }
}

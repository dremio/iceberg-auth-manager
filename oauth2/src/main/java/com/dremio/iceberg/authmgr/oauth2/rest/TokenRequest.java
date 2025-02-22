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

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import org.apache.iceberg.rest.RESTRequest;
import org.immutables.value.Value.Check;

/**
 * Common base for all requests to the token endpoint.
 *
 * @see ClientCredentialsTokenRequest
 * @see PasswordTokenRequest
 * @see AuthorizationCodeTokenRequest
 * @see DeviceAuthorizationRequest
 * @see RefreshTokenRequest
 * @see TokenExchangeRequest
 */
public interface TokenRequest extends RESTRequest, PostFormRequest, ClientRequest {

  /** The authorization grant type. */
  GrantType getGrantType();

  /**
   * OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope of
   * the access token as described by <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">Section 3.3</a>.
   *
   * <p>In case of refresh, the requested scope MUST NOT include any scope not originally granted by
   * the resource owner, and if omitted is treated as equal to the scope originally granted by the
   * resource owner.
   */
  @Nullable
  String getScope();

  /**
   * Additional parameters to be included in the request. This is useful for custom parameters that
   * are not covered by the standard OAuth2.0 specification.
   */
  Map<String, String> getExtraParameters();

  @Override
  default Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(getExtraParameters());
    data.putAll(ClientRequest.super.asFormParameters());
    data.put("grant_type", getGrantType().getCanonicalName());
    if (getScope() != null) {
      data.put("scope", getScope());
    }
    return Map.copyOf(data);
  }

  @Override
  @Check
  default void validate() {}

  interface Builder<T extends TokenRequest, B extends Builder<T, B>>
      extends ClientRequest.Builder<T, B> {

    @CanIgnoreReturnValue
    B scope(String scope);

    @CanIgnoreReturnValue
    B extraParameters(Map<String, ? extends String> extraParameters);

    T build();
  }
}

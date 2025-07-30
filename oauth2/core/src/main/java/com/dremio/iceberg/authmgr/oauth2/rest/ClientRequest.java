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
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
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
   * The client identifier as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">RFC 6749 Section 2.2</a>.
   */
  @Nullable
  String getClientId();

  /**
   * The client password as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">RFC 6749 Section 2.3.1</a>.
   */
  @Nullable
  @Redacted
  String getClientSecret();

  /**
   * The client assertion as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2">RFC 7523 Section 2.2.</a>.
   *
   * <p>This is typically a JWT (JSON Web Token) used to assert the identity of the client to the
   * authorization server. Only used when the client is using a client assertion for authentication
   * instead of a client secret.
   */
  @Nullable
  TypedToken getClientAssertion();

  @Override
  default Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>();
    if (getClientId() != null) {
      data.put("client_id", getClientId());
    }
    if (getClientSecret() != null) {
      data.put("client_secret", getClientSecret());
    }
    if (getClientAssertion() != null) {
      data.put("client_assertion", getClientAssertion().getPayload());
      data.put("client_assertion_type", getClientAssertion().getTokenType().toString());
    }
    return Map.copyOf(data);
  }

  interface Builder<T extends ClientRequest, B extends Builder<T, B>> {

    @CanIgnoreReturnValue
    B clientId(String clientId);

    @CanIgnoreReturnValue
    B clientSecret(String clientSecret);

    @CanIgnoreReturnValue
    B clientAssertion(TypedToken clientAssertion);

    T build();
  }
}

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
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * A <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">Token Request</a> using
 * the "authorization_code" grant type to obtain a new access token.
 *
 * <p>This class supports the <a href="https://datatracker.ietf.org/doc/html/rfc7636">PKCE</a>
 * extension to the OAuth 2.0 authorization code flow. The code verifier is only required if the
 * authorization server requires PKCE.
 *
 * <p>Example:
 *
 * <pre>{@code
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
 * &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * }</pre>
 */
@AuthManagerImmutable
public abstract class AuthorizationCodeTokenRequest implements TokenRequest {

  @Override
  public final GrantType getGrantType() {
    return GrantType.AUTHORIZATION_CODE;
  }

  /** The authorization code received from the authorization server. */
  public abstract String getCode();

  /** The redirect URI used in the initial request. */
  public abstract URI getRedirectUri();

  /**
   * The code verifier used in the initial request. This is only required if the authorization
   * server requires PKCE.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 Section 4.5</a>
   */
  @Nullable
  public abstract String getCodeVerifier();

  @Override
  public final Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(TokenRequest.super.asFormParameters());
    data.put("code", getCode());
    data.put("redirect_uri", getRedirectUri().toString());
    if (getCodeVerifier() != null) {
      data.put("code_verifier", getCodeVerifier());
    }
    return Map.copyOf(data);
  }

  public static Builder builder() {
    return ImmutableAuthorizationCodeTokenRequest.builder();
  }

  public interface Builder extends TokenRequest.Builder<AuthorizationCodeTokenRequest, Builder> {
    @CanIgnoreReturnValue
    Builder code(String code);

    @CanIgnoreReturnValue
    Builder redirectUri(URI redirectUri);

    @CanIgnoreReturnValue
    Builder codeVerifier(@Nullable String codeVerifier);
  }
}

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

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.ImmutableAccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.ImmutableRefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import org.apache.iceberg.rest.RESTResponse;
import org.immutables.value.Value.Check;
import org.immutables.value.Value.Redacted;

/**
 * Successful response in reply to {@link ClientCredentialsTokenRequest},{@link
 * PasswordTokenRequest}, {@link AuthorizationCodeTokenRequest}, {@link DeviceAuthorizationRequest},
 * {@link RefreshTokenRequest}, or {@link TokenExchangeRequest}.
 *
 * <p>These responses share the same schema, which is declared in <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">Section 5.1</a>.
 *
 * <p>Example of response:
 *
 * <pre>{@code
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "access_token":"2YotnFZFEjr1zCsicMWpAA",
 *   "token_type":"example",
 *   "expires_in":3600,
 *   "example_parameter":"example_value"
 * }
 * }</pre>
 *
 * <p>A token response is also a flattened representation of a {@link Tokens} pair.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">Access Token
 *     Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.5">Device Access Token
 *     Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693/#section-2.2.1">Token Exchange
 *     Response</a>
 */
@AuthManagerImmutable
@JsonSerialize(as = ImmutableTokenResponse.class)
@JsonDeserialize(as = ImmutableTokenResponse.class)
@JsonInclude(Include.NON_EMPTY)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public interface TokenResponse extends RESTResponse {

  @Override
  @Check
  default void validate() {}

  /** Convert this response to a {@link Tokens} pair using the provided clock. */
  default Tokens asTokens(Clock clock) {

    Instant now = clock.instant();

    Integer accessExpiresIn = getAccessTokenExpiresInSeconds();
    AccessToken accessToken =
        ImmutableAccessToken.builder()
            .tokenType(getTokenType())
            .payload(getAccessTokenPayload())
            .expirationTime(accessExpiresIn == null ? null : now.plusSeconds(accessExpiresIn))
            .build();

    String refreshTokenPayload = getRefreshTokenPayload();
    Integer refreshExpiresIn = getRefreshTokenExpiresInSeconds();
    RefreshToken refreshToken =
        refreshTokenPayload == null
            ? null
            : ImmutableRefreshToken.builder()
                .payload(refreshTokenPayload)
                .expirationTime(refreshExpiresIn == null ? null : now.plusSeconds(refreshExpiresIn))
                .build();

    return Tokens.of(accessToken, refreshToken);
  }

  /**
   * The type of the token issued as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-7.1">Section 7.1</a>. Value is
   * case-insensitive.
   *
   * <p>This is typically "Bearer".
   */
  String getTokenType();

  /** The access token issued by the authorization server. */
  @JsonProperty("access_token")
  @Redacted
  String getAccessTokenPayload();

  /**
   * RECOMMENDED. The lifetime in seconds of the access token. For example, the value "3600" denotes
   * that the access token will expire in one hour from the time the response was generated. If
   * omitted, the authorization server SHOULD provide the expiration time via other means or
   * document the default value.
   */
  @Nullable
  @JsonProperty("expires_in")
  Integer getAccessTokenExpiresInSeconds();

  /**
   * OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
   * authorization grant as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">Section 6</a>.
   *
   * <p>Note: in the client credentials flow (grant type {@link GrantType#CLIENT_CREDENTIALS}), as
   * per <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3">Section 4.4.3</a>, "A
   * refresh token SHOULD NOT be included". Keycloak indeed does not include a refresh token in the
   * response to a client credentials flow, unless the client is configured with the attribute
   * "client_credentials.use_refresh_token" set to "true".
   */
  @Nullable
  @JsonProperty("refresh_token")
  @Redacted
  String getRefreshTokenPayload();

  /**
   * Not in the OAuth2 spec, but used by Keycloak. The lifetime in seconds of the refresh token,
   * when a refresh token is included in the response.
   */
  @Nullable
  @JsonProperty("refresh_expires_in")
  Integer getRefreshTokenExpiresInSeconds();

  /**
   * OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope of
   * the access token as described by <a
   * href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">Section 3.3</a>.
   */
  @Nullable
  String getScope();

  /**
   * For the Token Exchange grant only: REQUIRED. An identifier, as described in <a
   * href="https://datatracker.ietf.org/doc/html/rfc8693/#section-3">Section 3</a>, for the
   * representation of the issued security token.
   *
   * <p>Note: some OAuth2 providers do not return this field in a token exchange response, even
   * though it is required by the spec.
   *
   * <p>This field is currently unused by this OAuth2 agent.
   */
  @Nullable
  URI getIssuedTokenType();

  @JsonAnyGetter
  Map<String, Object> getExtraParameters();
}

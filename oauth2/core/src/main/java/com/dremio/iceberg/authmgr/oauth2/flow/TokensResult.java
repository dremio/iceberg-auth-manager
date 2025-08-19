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
package com.dremio.iceberg.authmgr.oauth2.flow;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import jakarta.annotation.Nullable;
import java.time.Instant;
import org.immutables.value.Value;

/**
 * The result of a successful token request, including the issued tokens and the time they were
 * issued.
 */
@AuthManagerImmutable
public abstract class TokensResult {

  public static TokensResult of(AccessToken token) {
    return ImmutableTokensResult.builder().tokens(new Tokens(token, null)).build();
  }

  public static TokensResult of(Tokens tokens, @Nullable Instant issuedAt) {
    return ImmutableTokensResult.builder().tokens(tokens).issuedAt(issuedAt).build();
  }

  /** The issued tokens. */
  public abstract Tokens getTokens();

  /** The time the tokens were issued. */
  @Nullable
  public abstract Instant getIssuedAt();

  /**
   * The resolved expiration time of the access token, taking into account the response's {@code
   * expires_in} field and the JWT claims, if applicable.
   */
  @Value.Derived
  @Nullable
  public Instant getExpirationTime() {
    Instant exp = getResponseExpirationTime();
    return exp != null ? exp : getJwtExpirationTime();
  }

  /**
   * Returns true if the token is expired at the given time, inspecting the token's expiration time
   * and its JWT claims, if applicable. Note that if no expiration time is found, this method
   * returns false.
   */
  public boolean isExpired(Instant when) {
    Instant exp = getExpirationTime();
    return exp != null && !exp.isAfter(when);
  }

  /** The access token expiration time as reported in the token response, if any. */
  @Value.Lazy
  @Nullable
  Instant getResponseExpirationTime() {
    return getIssuedAt() != null && getTokens().getAccessToken().getLifetime() > 0
        ? getIssuedAt().plusSeconds(getTokens().getAccessToken().getLifetime())
        : null;
  }

  /**
   * The JWT token expiration time, if the token is a JWT token and contains an expiration claim.
   */
  @Value.Lazy
  @Nullable
  Instant getJwtExpirationTime() {
    try {
      return JWTParser.parse(getTokens().getAccessToken().getValue())
          .getJWTClaimsSet()
          .getExpirationTime()
          .toInstant();
    } catch (Exception ignored) {
      return null;
    }
  }
}

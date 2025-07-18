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
package com.dremio.iceberg.authmgr.oauth2.token;

import com.auth0.jwt.JWT;
import jakarta.annotation.Nullable;
import java.time.Instant;
import org.immutables.value.Value;

/** A token issued by the authorization server. */
public interface Token {

  /** The raw text of the token. */
  String getPayload();

  /** The token expiration time as reported in the token response, if any. */
  @Nullable
  Instant getExpirationTime();

  /**
   * The JWT token expiration time, if the token is a JWT token and contains an expiration claim.
   */
  @Value.Lazy
  @Nullable
  default Instant getJwtExpirationTime() {
    try {
      return JWT.decode(getPayload()).getExpiresAtAsInstant();
    } catch (Exception ignored) {
      return null;
    }
  }

  /**
   * The resolved expiration time of the token, taking into account the token's expiration time and
   * its JWT claims, if applicable.
   */
  @Value.Derived
  @Nullable
  default Instant getResolvedExpirationTime() {
    Instant exp = getExpirationTime();
    return exp != null ? exp : getJwtExpirationTime();
  }

  /**
   * Returns true if the token is expired at the given time, inspecting the token's expiration time
   * and its JWT claims, if applicable. Note that if no expiration time is found, this method
   * returns false.
   */
  default boolean isExpired(Instant when) {
    Instant exp = getResolvedExpirationTime();
    return exp != null && !exp.isAfter(when);
  }
}

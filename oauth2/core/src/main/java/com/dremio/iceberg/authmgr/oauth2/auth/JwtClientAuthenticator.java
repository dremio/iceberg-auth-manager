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
package com.dremio.iceberg.authmgr.oauth2.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest.Builder;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public abstract class JwtClientAuthenticator implements StandardClientAuthenticator {

  public static final URI CLIENT_ASSERTION_TYPE =
      URI.create("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

  public static final Duration DEFAULT_TOKEN_LIFESPAN = Duration.ofMinutes(5);

  public abstract JwtAssertion getClientAssertionConfig();

  public abstract URI getTokenEndpoint();

  public abstract Clock getClock();

  @Override
  public final <R extends ClientRequest, B extends Builder<R, B>> void authenticate(
      Builder<R, B> request, Map<String, String> headers, @Nullable Tokens currentTokens) {
    Algorithm algorithm = getAlgorithm();
    String jwt = createJwt(algorithm);
    request.clientAssertion(jwt).clientAssertionType(CLIENT_ASSERTION_TYPE);
  }

  protected abstract Algorithm getAlgorithm();

  String createJwt(Algorithm algorithm) {
    Instant now = getClock().instant();
    JwtAssertion config = getClientAssertionConfig();
    JWTCreator.Builder builder =
        JWT.create()
            .withJWTId(UUID.randomUUID().toString())
            .withIssuer(config.getIssuer().orElse(getClientId()))
            .withSubject(config.getIssuer().orElse(getClientId()))
            .withAudience(config.getAudience().orElse(getTokenEndpoint().toString()))
            .withIssuedAt(now)
            .withExpiresAt(now.plus(config.getTokenLifespan().orElse(DEFAULT_TOKEN_LIFESPAN)));
    config.getExtraClaims().forEach(builder::withClaim);
    return builder.sign(algorithm);
  }
}

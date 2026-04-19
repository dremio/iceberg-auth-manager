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
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.JWTBearerGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.1"JWT
 * bearer</a> grant.
 */
@AuthManagerImmutable
abstract class JwtBearerFlow extends AbstractFlow {

  interface Builder extends AbstractFlow.Builder<JwtBearerFlow, Builder> {
    @CanIgnoreReturnValue
    Builder assertionStage(CompletionStage<String> assertionStage);
  }

  @Override
  public final GrantType getGrantType() {
    return GrantType.JWT_BEARER;
  }

  abstract CompletionStage<String> assertionStage();

  @Override
  public CompletionStage<TokensResult> fetchNewTokens() {
    return assertionStage()
        .thenApply(JwtBearerFlow::toJwtBearerGrant)
        .thenCompose(this::invokeTokenEndpoint);
  }

  private static JWTBearerGrant toJwtBearerGrant(String assertion) {
    Objects.requireNonNull(
        assertion, "Cannot execute JWT bearer grant: missing required assertion");
    // Delegate parsing to JWTBearerGrant.parse() so we make no structural assumptions
    // about the assertion. It handles both signed (JWS) and encrypted (JWE) JWTs,
    // and rejects unsecured plain JWTs as required by RFC 7523.
    try {
      return JWTBearerGrant.parse(
          Map.of(
              "grant_type", List.of(GrantType.JWT_BEARER.getValue()),
              "assertion", List.of(assertion)));
    } catch (ParseException e) {
      throw new IllegalArgumentException("Failed to create JWT Bearer grant: " + e.getMessage(), e);
    }
  }
}

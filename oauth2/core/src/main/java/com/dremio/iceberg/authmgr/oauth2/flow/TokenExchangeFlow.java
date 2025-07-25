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

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8693">Token
 * Exchange</a> flow.
 */
@AuthManagerImmutable
abstract class TokenExchangeFlow extends AbstractFlow implements InitialFlow {

  interface Builder extends AbstractFlow.Builder<TokenExchangeFlow, Builder> {
    @CanIgnoreReturnValue
    Builder subjectTokenStage(CompletionStage<TypedToken> subjectTokenStage);

    @CanIgnoreReturnValue
    Builder actorTokenStage(CompletionStage<TypedToken> actorTokenStage);
  }

  @Override
  public GrantType getGrantType() {
    return GrantType.TOKEN_EXCHANGE;
  }

  abstract CompletionStage<TypedToken> subjectTokenStage();

  abstract CompletionStage<TypedToken> actorTokenStage();

  @Override
  public CompletionStage<Tokens> fetchNewTokens() {
    return subjectTokenStage()
        .thenCombine(
            actorTokenStage(),
            (subjectToken, actorToken) -> {
              Objects.requireNonNull(
                  subjectToken, "Cannot execute token exchange: missing required subject token");
              return TokenExchangeRequest.builder()
                  .subjectToken(subjectToken.getPayload())
                  .subjectTokenType(subjectToken.getTokenType())
                  .actorToken(actorToken == null ? null : actorToken.getPayload())
                  .actorTokenType(actorToken == null ? null : actorToken.getTokenType())
                  .resource(getSpec().getTokenExchangeConfig().getResource().orElse(null))
                  .audience(getSpec().getTokenExchangeConfig().getAudience().orElse(null))
                  .requestedTokenType(getSpec().getTokenExchangeConfig().getRequestedTokenType());
            })
        .thenCompose(request -> invokeTokenEndpoint(null, request));
  }
}

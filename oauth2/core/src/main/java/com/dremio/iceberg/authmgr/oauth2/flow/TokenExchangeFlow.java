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

import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8693">Token
 * Exchange</a> flow.
 */
@AuthManagerImmutable
abstract class TokenExchangeFlow extends AbstractFlow {

  interface Builder extends AbstractFlow.Builder<TokenExchangeFlow, Builder> {
    @CanIgnoreReturnValue
    Builder subjectTokenStage(CompletionStage<AccessToken> subjectTokenStage);

    @CanIgnoreReturnValue
    Builder actorTokenStage(CompletionStage<AccessToken> actorTokenStage);
  }

  @Override
  public final GrantType getGrantType() {
    return GrantType.TOKEN_EXCHANGE;
  }

  abstract CompletionStage<AccessToken> subjectTokenStage();

  abstract CompletionStage<AccessToken> actorTokenStage();

  @Override
  public CompletionStage<TokensResult> fetchNewTokens() {
    return subjectTokenStage()
        .thenCombine(
            actorTokenStage(),
            (subjectToken, actorToken) -> {
              Objects.requireNonNull(
                  subjectToken, "Cannot execute token exchange: missing required subject token");
              TokenExchangeConfig tokenExchangeConfig = getConfig().getTokenExchangeConfig();
              return newTokenExchangeGrant(subjectToken, actorToken, tokenExchangeConfig);
            })
        .thenCompose(this::invokeTokenEndpoint);
  }

  @Override
  TokenRequest.Builder newTokenRequestBuilder(AuthorizationGrant grant) {
    TokenRequest.Builder builder = super.newTokenRequestBuilder(grant);
    TokenExchangeConfig tokenExchangeConfig = getConfig().getTokenExchangeConfig();
    tokenExchangeConfig.getResource().ifPresent(builder::resources);
    return builder;
  }

  private static TokenExchangeGrant newTokenExchangeGrant(
      AccessToken subjectToken, AccessToken actorToken, TokenExchangeConfig tokenExchangeConfig) {
    return new TokenExchangeGrant(
        subjectToken,
        subjectToken.getIssuedTokenType() == null
            ? TokenTypeURI.ACCESS_TOKEN
            : subjectToken.getIssuedTokenType(),
        actorToken,
        actorToken == null
            ? null
            : actorToken.getIssuedTokenType() == null
                ? TokenTypeURI.ACCESS_TOKEN
                : actorToken.getIssuedTokenType(),
        tokenExchangeConfig.getRequestedTokenType(),
        tokenExchangeConfig.getAudience().map(List::of).orElse(List.of()));
  }
}

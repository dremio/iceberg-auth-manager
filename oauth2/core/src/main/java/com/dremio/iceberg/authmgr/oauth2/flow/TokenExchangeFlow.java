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
import com.dremio.iceberg.authmgr.oauth2.rest.TokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import jakarta.annotation.Nullable;
import java.util.Objects;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8693">Token
 * Exchange</a> flow.
 */
class TokenExchangeFlow extends AbstractFlow {

  private final TokenExchangeConfig tokenExchangeConfig;

  TokenExchangeFlow(FlowContext context) {
    super(context);
    tokenExchangeConfig = context.getTokenExchangeConfig();
  }

  @Override
  public Tokens fetchNewTokens(Tokens currentTokens) {
    AccessToken accessToken = currentTokens == null ? null : currentTokens.getAccessToken();

    TypedToken subjectToken =
        tokenExchangeConfig.getSubjectTokenProvider().provideToken(accessToken);
    TypedToken actorToken = tokenExchangeConfig.getActorTokenProvider().provideToken(accessToken);

    return fetchNewTokens(currentTokens, subjectToken, actorToken);
  }

  protected Tokens fetchNewTokens(
      Tokens currentTokens, TypedToken subjectToken, @Nullable TypedToken actorToken) {
    Objects.requireNonNull(
        subjectToken, "Cannot execute token exchange: missing required subject token");

    TokenExchangeRequest.Builder request =
        TokenExchangeRequest.builder()
            .subjectToken(subjectToken.getPayload())
            .subjectTokenType(subjectToken.getTokenType())
            .actorToken(actorToken == null ? null : actorToken.getPayload())
            .actorTokenType(actorToken == null ? null : actorToken.getTokenType())
            .resource(tokenExchangeConfig.getResource().orElse(null))
            .audience(tokenExchangeConfig.getAudience().orElse(null))
            .requestedTokenType(tokenExchangeConfig.getRequestedTokenType());

    return invokeTokenEndpoint(currentTokens, request);
  }
}

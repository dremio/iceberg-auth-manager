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

import com.dremio.iceberg.authmgr.oauth2.rest.TokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

/**
 * A specialized {@link TokenExchangeFlow} that is used to refresh access tokens, for the Iceberg
 * dialect only.
 */
@AuthManagerImmutable
abstract class IcebergRefreshTokenFlow extends AbstractFlow {

  interface Builder extends AbstractFlow.Builder<IcebergRefreshTokenFlow, Builder> {}

  @Override
  public CompletionStage<Tokens> fetchNewTokens(Tokens currentTokens) {
    Objects.requireNonNull(currentTokens, "currentTokens is null");
    Objects.requireNonNull(
        currentTokens.getAccessToken(), "currentTokens.getAccessToken() is null");

    TypedToken subjectToken = TypedToken.of(currentTokens.getAccessToken());

    TokenExchangeRequest.Builder request =
        TokenExchangeRequest.builder()
            .subjectToken(subjectToken.getPayload())
            .subjectTokenType(subjectToken.getTokenType())
            .resource(getSpec().getTokenExchangeConfig().getResource().orElse(null))
            .audience(getSpec().getTokenExchangeConfig().getAudience().orElse(null))
            .requestedTokenType(getSpec().getTokenExchangeConfig().getRequestedTokenType());

    return invokeTokenEndpoint(currentTokens, request);
  }
}

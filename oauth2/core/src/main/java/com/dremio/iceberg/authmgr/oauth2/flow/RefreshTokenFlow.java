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
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import java.time.Instant;
import java.util.concurrent.CompletionStage;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">Token
 * Refresh</a> flow.
 */
@AuthManagerImmutable
abstract class RefreshTokenFlow extends AbstractFlow {

  interface Builder extends AbstractFlow.Builder<RefreshTokenFlow, Builder> {

    @CanIgnoreReturnValue
    Builder refreshToken(RefreshToken refreshToken);
  }

  @Override
  public final GrantType getGrantType() {
    return GrantType.REFRESH_TOKEN;
  }

  abstract RefreshToken getRefreshToken();

  @Override
  public CompletionStage<TokensResult> fetchNewTokens() {
    return invokeTokenEndpoint(new RefreshTokenGrant(getRefreshToken()));
  }

  @Override
  TokensResult toTokensResult(AccessTokenResponse response) {
    Instant now = getRuntime().getClock().instant();
    Tokens tokens = response.toSuccessResponse().getTokens();
    // if the server doesn't return a new refresh token, keep using the current one
    if (tokens.getRefreshToken() == null) {
      tokens = new Tokens(tokens.getAccessToken(), getRefreshToken());
    }
    return TokensResult.of(tokens, now, response.getCustomParameters());
  }
}

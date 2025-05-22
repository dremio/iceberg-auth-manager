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

import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import java.util.Objects;

/**
 * A specialized {@link TokenExchangeFlow} that is used to refresh access tokens, for the Iceberg
 * dialect only.
 */
class IcebergRefreshTokenFlow extends TokenExchangeFlow {

  IcebergRefreshTokenFlow(FlowContext context) {
    super(context);
  }

  @Override
  public Tokens fetchNewTokens(Tokens currentTokens) {
    Objects.requireNonNull(currentTokens, "currentTokens is null");
    Objects.requireNonNull(
        currentTokens.getAccessToken(), "currentTokens.getAccessToken() is null");
    TypedToken subjectToken = TypedToken.of(currentTokens.getAccessToken());
    return fetchNewTokens(currentTokens, subjectToken, null);
  }
}

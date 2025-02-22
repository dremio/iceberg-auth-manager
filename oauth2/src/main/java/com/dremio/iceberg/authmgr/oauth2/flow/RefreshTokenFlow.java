/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.flow;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.rest.RefreshTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.util.Objects;
import org.apache.iceberg.rest.RESTClient;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">Token
 * Refresh</a> flow.
 */
class RefreshTokenFlow extends AbstractFlow {

  RefreshTokenFlow(OAuth2AgentSpec spec, RESTClient restClient, EndpointResolver endpointResolver) {
    super(spec, restClient, endpointResolver);
  }

  @Override
  public Tokens fetchNewTokens(@Nullable Tokens currentTokens) {
    Objects.requireNonNull(currentTokens, "currentTokens is null");
    Objects.requireNonNull(
        currentTokens.getRefreshToken(), "currentTokens.getRefreshTokens() is null");
    RefreshTokenRequest.Builder request =
        RefreshTokenRequest.builder().refreshToken(currentTokens.getRefreshToken().getPayload());
    Tokens tokens = invokeTokenEndpoint(currentTokens, request);
    if (tokens.getRefreshToken() == null) {
      tokens = Tokens.of(tokens.getAccessToken(), currentTokens.getRefreshToken());
    }
    return tokens;
  }
}

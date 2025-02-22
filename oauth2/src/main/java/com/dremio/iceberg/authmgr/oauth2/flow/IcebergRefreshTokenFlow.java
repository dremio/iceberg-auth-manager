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
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.apache.iceberg.rest.RESTClient;

/**
 * A specialized {@link TokenExchangeFlow} that is used to refresh access tokens, for the Iceberg
 * dialect only.
 */
class IcebergRefreshTokenFlow extends TokenExchangeFlow {

  IcebergRefreshTokenFlow(
      OAuth2AgentSpec spec, RESTClient restClient, EndpointResolver endpointResolver) {
    super(spec, restClient, endpointResolver);
  }

  @Override
  public Tokens fetchNewTokens(Tokens currentTokens) {
    Objects.requireNonNull(currentTokens, "currentTokens is null");
    Objects.requireNonNull(
        currentTokens.getAccessToken(), "currentTokens.getAccessToken() is null");
    TypedToken subjectToken = TypedToken.of(currentTokens.getAccessToken());
    return fetchNewTokens(currentTokens, subjectToken, null);
  }

  @Override
  protected Map<String, String> getHeaders(@Nullable Tokens currentTokens) {
    Map<String, String> headers = new HashMap<>();
    headers.put("Content-Type", PostFormRequest.CONTENT_TYPE);
    // With Iceberg dialect servers must understand a token exchange request with either
    // a Bearer or a Basic auth header. We use Basic if available, otherwise Bearer,
    // because the latter is non-standard.
    String header =
        getServiceAccount()
            .asBasicAuthHeader()
            .orElseGet(
                () ->
                    "Bearer "
                        + Objects.requireNonNull(currentTokens).getAccessToken().getPayload());
    headers.put("Authorization", header);
    return headers;
  }
}

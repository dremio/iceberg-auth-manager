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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import org.apache.iceberg.rest.RESTClient;

/**
 * An implementation of the <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.4">Client Credentials Grant</a>
 * flow for the Iceberg dialect.
 */
class IcebergClientCredentialsFlow extends AbstractFlow {

  IcebergClientCredentialsFlow(
      OAuth2AgentSpec spec, RESTClient restClient, EndpointResolver endpointResolver) {
    super(spec, restClient, endpointResolver);
  }

  @Override
  public Tokens fetchNewTokens(@Nullable Tokens currentTokens) {
    ClientCredentialsTokenRequest.Builder request = ClientCredentialsTokenRequest.builder();
    return invokeTokenEndpoint(currentTokens, request);
  }

  @Override
  protected Map<String, String> getHeaders(@Nullable Tokens currentTokens) {
    Map<String, String> headers = new HashMap<>();
    headers.put("Content-Type", PostFormRequest.CONTENT_TYPE);
    // no authorization header
    return headers;
  }

  @Override
  protected <REQ extends ClientRequest> void prepareRequestBody(
      ClientRequest.Builder<REQ, ?> request) {
    ServiceAccount idAndSecret = getServiceAccount();
    idAndSecret.getClientId().ifPresent(request::clientId);
    idAndSecret.getClientSecret().ifPresent(s -> request.clientSecret(s.getSecret()));
  }
}

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
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenRequest.Builder;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenResponse;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.apache.iceberg.rest.RESTClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Infrastructure shared by all flows.
 *
 * <p>The general behavior adopted by the OAuth2 agent wrt to client authentication is as follows:
 *
 * <p>For the standard dialect:
 *
 * <ul>
 *   <li>For confidential clients:
 *       <ol>
 *         <li>Authenticate the client with a Basic authentication header (while it is also possible
 *             to authenticate using {@code client_id} + {@code client_secret} in the request body,
 *             the OAuth 2.0 spec considers this method less secure, so we don't use it);
 *         <li>Do NOT include {@code client_id} nor {@code client_secret} in the request body, since
 *             the spec also forbids more than one authentication method in each request.
 *       </ol>
 *   <li>For public clients:
 *       <ol>
 *         <li>Do not include any Basic authentication header (since there is no client secret);
 *         <li>But do include {@code client_id} in the request body, in order to identify the client
 *             (according to the spec, including {@code client_id} is mandatory for public clients
 *             using the Authorization Code Grant, and optional for other grants – but we always
 *             include it).
 *       </ol>
 * </ul>
 *
 * <p>For the Iceberg dialect:
 *
 * <ul>
 *   <li>For initial token fetches (using the "client_credentials" grant): include {@code client_id}
 *       and {@code client_secret} in the request body.
 *   <li>For token refreshes (using the token exchange grant): include the access token in the
 *       request headers (Bearer token authentication), and in the request body, as the subject
 *       token.
 * </ul>
 */
abstract class AbstractFlow implements Flow {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFlow.class);

  private final OAuth2AgentSpec spec;
  private final RESTClient restClient;
  private final EndpointResolver endpointResolver;

  protected AbstractFlow(
      OAuth2AgentSpec spec, RESTClient restClient, EndpointResolver endpointResolver) {
    this.spec = spec;
    this.restClient = restClient;
    this.endpointResolver = endpointResolver;
  }

  protected URI getResolvedTokenEndpoint() {
    return endpointResolver.getResolvedTokenEndpoint();
  }

  protected Map<String, String> getExtraRequestParameters() {
    return spec.getBasicConfig().getExtraRequestParameters();
  }

  protected Optional<String> getScopesAsString() {
    return FlowUtils.scopesAsString(spec.getBasicConfig().getScopes());
  }

  protected ServiceAccount getServiceAccount() {
    return spec.getBasicConfig();
  }

  protected <REQ extends TokenRequest> Tokens invokeTokenEndpoint(
      @Nullable Tokens currentTokens, Builder<REQ, ?> builder) {
    builder.extraParameters(getExtraRequestParameters());
    getScopesAsString().ifPresent(builder::scope);
    prepareRequestBody(builder);
    REQ request = builder.build();
    LOGGER.debug("Invoking token endpoint: {}", request);
    TokenResponse response =
        restClient.postForm(
            getResolvedTokenEndpoint().toString(),
            request.asFormParameters(),
            TokenResponse.class,
            getHeaders(currentTokens),
            FlowErrorHandler.INSTANCE);
    LOGGER.debug("Token endpoint response: {}", response);
    return response.asTokens(spec.getRuntimeConfig().getClock());
  }

  protected DeviceAuthorizationResponse invokeDeviceAuthEndpoint(@Nullable Tokens currentTokens) {
    DeviceAuthorizationRequest.Builder builder = DeviceAuthorizationRequest.builder();
    getScopesAsString().ifPresent(builder::scope);
    prepareRequestBody(builder);
    DeviceAuthorizationRequest request = builder.build();
    LOGGER.debug("Invoking device auth endpoint: {}", request);
    DeviceAuthorizationResponse response =
        restClient.postForm(
            endpointResolver.getResolvedDeviceAuthorizationEndpoint().toString(),
            request.asFormParameters(),
            DeviceAuthorizationResponse.class,
            getHeaders(currentTokens),
            FlowErrorHandler.INSTANCE);
    LOGGER.debug("Device auth endpoint response: {}", response);
    return response;
  }

  protected <REQ extends ClientRequest> void prepareRequestBody(
      ClientRequest.Builder<REQ, ?> request) {
    ServiceAccount idAndSecret = getServiceAccount();
    if (idAndSecret.isPublicClient()) {
      idAndSecret.getClientId().ifPresent(request::clientId);
    }
  }

  protected Map<String, String> getHeaders(@Nullable Tokens currentTokens) {
    Map<String, String> headers = new HashMap<>();
    headers.put("Content-Type", PostFormRequest.CONTENT_TYPE);
    getServiceAccount()
        .asBasicAuthHeader()
        .ifPresent(header -> headers.put("Authorization", header));
    return headers;
  }
}

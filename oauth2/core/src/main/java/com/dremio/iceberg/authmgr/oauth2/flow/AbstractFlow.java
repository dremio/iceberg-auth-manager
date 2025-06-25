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
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticator;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenResponse;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Infrastructure shared by all flows. */
abstract class AbstractFlow implements Flow {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFlow.class);

  interface Builder<F extends AbstractFlow, B extends Builder<F, B>> {

    @CanIgnoreReturnValue
    B spec(OAuth2AgentSpec spec);

    @CanIgnoreReturnValue
    B executor(ScheduledExecutorService executor);

    @CanIgnoreReturnValue
    B restClient(RESTClient restClient);

    @CanIgnoreReturnValue
    B endpointProvider(EndpointProvider endpointProvider);

    @CanIgnoreReturnValue
    B clientAuthenticator(ClientAuthenticator clientAuthenticator);

    F build();
  }

  abstract OAuth2AgentSpec getSpec();

  abstract ScheduledExecutorService getExecutor();

  abstract RESTClient getRestClient();

  abstract EndpointProvider getEndpointProvider();

  abstract ClientAuthenticator getClientAuthenticator();

  protected <REQ extends TokenRequest> CompletionStage<Tokens> invokeTokenEndpoint(
      @Nullable Tokens currentTokens, TokenRequest.Builder<REQ, ?> builder) {
    URI tokenEndpoint = getEndpointProvider().getResolvedTokenEndpoint();
    builder.extraParameters(getSpec().getBasicConfig().getExtraRequestParameters());
    ConfigUtils.scopesAsString(getSpec().getBasicConfig().getScopes()).ifPresent(builder::scope);
    Map<String, String> headers = getHeaders();
    getClientAuthenticator().authenticate(builder, headers, currentTokens);
    REQ request = builder.build();
    return CompletableFuture.supplyAsync(
            () -> {
              LOGGER.debug(
                  "[{}] Invoking token endpoint: headers: {} body: {}",
                  getSpec().getRuntimeConfig().getAgentName(),
                  filterSensitiveData(headers),
                  request);
              return getRestClient()
                  .postForm(
                      tokenEndpoint.toString(),
                      request.asFormParameters(),
                      TokenResponse.class,
                      headers,
                      FlowErrorHandler.INSTANCE);
            },
            getExecutor())
        .whenComplete((resp, error) -> log("token endpoint", resp, error))
        .thenApply(resp -> resp.asTokens(getSpec().getRuntimeConfig().getClock()));
  }

  protected CompletionStage<DeviceAuthorizationResponse> invokeDeviceAuthEndpoint(
      @Nullable Tokens currentTokens) {
    URI deviceAuthorizationEndpoint =
        Objects.requireNonNull(getEndpointProvider().getResolvedDeviceAuthorizationEndpoint());
    DeviceAuthorizationRequest.Builder builder = DeviceAuthorizationRequest.builder();
    ConfigUtils.scopesAsString(getSpec().getBasicConfig().getScopes()).ifPresent(builder::scope);
    Map<String, String> headers = getHeaders();
    getClientAuthenticator().authenticate(builder, headers, currentTokens);
    DeviceAuthorizationRequest request = builder.build();
    return CompletableFuture.supplyAsync(
            () -> {
              LOGGER.debug(
                  "[{}] Invoking device auth endpoint: headers: {} body: {}",
                  getSpec().getRuntimeConfig().getAgentName(),
                  filterSensitiveData(headers),
                  request);
              return getRestClient()
                  .postForm(
                      deviceAuthorizationEndpoint.toString(),
                      request.asFormParameters(),
                      DeviceAuthorizationResponse.class,
                      headers,
                      FlowErrorHandler.INSTANCE);
            },
            getExecutor())
        .whenComplete((resp, error) -> log("device auth endpoint", resp, error));
  }

  private void log(String endpoint, RESTResponse response, Throwable error) {
    String agentName = getSpec().getRuntimeConfig().getAgentName();
    if (error == null) {
      LOGGER.debug("[{}] Received response from {}: {}", agentName, endpoint, response);
    } else {
      LOGGER.debug("[{}] Error invoking {}: {}", agentName, endpoint, error.toString());
    }
  }

  private static Map<String, String> getHeaders() {
    Map<String, String> headers = new HashMap<>();
    headers.put("Content-Type", PostFormRequest.CONTENT_TYPE);
    return headers;
  }

  private static Map<String, String> filterSensitiveData(Map<String, String> headers) {
    Map<String, String> redactedHeaders = new HashMap<>(headers);
    if (redactedHeaders.containsKey("Authorization")) {
      redactedHeaders.put("Authorization", "****");
    }
    return redactedHeaders;
  }
}

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

import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenResponse;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Infrastructure shared by all flows. */
abstract class AbstractFlow implements Flow {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFlow.class);

  private final FlowContext context;

  protected AbstractFlow(FlowContext context) {
    this.context = context;
  }

  protected <REQ extends TokenRequest> Tokens invokeTokenEndpoint(
      @Nullable Tokens currentTokens, TokenRequest.Builder<REQ, ?> builder) {
    URI tokenEndpoint = context.getEndpointProvider().getResolvedTokenEndpoint();
    builder.extraParameters(context.getExtraRequestParameters());
    context.getScopesAsString().ifPresent(builder::scope);
    Map<String, String> headers = getHeaders();
    context.getClientAuthenticator().authenticate(builder, headers, currentTokens);
    REQ request = builder.build();
    LOGGER.debug(
        "Invoking token endpoint: headers: {} body: {}", filterSensitiveData(headers), request);
    TokenResponse response =
        context
            .getRestClient()
            .postForm(
                tokenEndpoint.toString(),
                request.asFormParameters(),
                TokenResponse.class,
                headers,
                FlowErrorHandler.INSTANCE);
    LOGGER.debug("Token endpoint response: {}", response);
    return response.asTokens(context.getRuntimeConfig().getClock());
  }

  protected DeviceAuthorizationResponse invokeDeviceAuthEndpoint(@Nullable Tokens currentTokens) {
    URI deviceAuthorizationEndpoint =
        Objects.requireNonNull(
            context.getEndpointProvider().getResolvedDeviceAuthorizationEndpoint());
    DeviceAuthorizationRequest.Builder builder = DeviceAuthorizationRequest.builder();
    context.getScopesAsString().ifPresent(builder::scope);
    Map<String, String> headers = getHeaders();
    context.getClientAuthenticator().authenticate(builder, headers, currentTokens);
    DeviceAuthorizationRequest request = builder.build();
    LOGGER.debug(
        "Invoking device auth endpoint: headers: {} body: {}",
        filterSensitiveData(headers),
        request);
    DeviceAuthorizationResponse response =
        context
            .getRestClient()
            .postForm(
                deviceAuthorizationEndpoint.toString(),
                request.asFormParameters(),
                DeviceAuthorizationResponse.class,
                headers,
                FlowErrorHandler.INSTANCE);
    LOGGER.debug("Device auth endpoint response: {}", response);
    return response;
  }

  private Map<String, String> getHeaders() {
    Map<String, String> headers = new HashMap<>();
    headers.put("Content-Type", PostFormRequest.CONTENT_TYPE);
    return headers;
  }

  private Map<String, String> filterSensitiveData(Map<String, String> headers) {
    Map<String, String> redactedHeaders = new HashMap<>(headers);
    if (redactedHeaders.containsKey("Authorization")) {
      redactedHeaders.put("Authorization", "****");
    }
    return redactedHeaders;
  }
}

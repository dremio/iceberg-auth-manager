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
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticatorFactory;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProviderFactory;
import jakarta.annotation.Nullable;
import org.apache.iceberg.rest.RESTClient;

public final class FlowContextFactory {

  private FlowContextFactory() {}

  public static FlowContext createFlowContext(OAuth2AgentSpec spec, RESTClient restClient) {
    EndpointProvider endpointProvider =
        EndpointProviderFactory.createEndpointProvider(spec, restClient);
    ClientAuthenticator clientAuthenticator = ClientAuthenticatorFactory.createAuthenticator(spec);
    return ImmutableFlowContext.builder()
        .restClient(restClient)
        .endpointProvider(endpointProvider)
        .clientAuthenticator(clientAuthenticator)
        .clientId(spec.getBasicConfig().getClientId())
        .scopesAsString(ConfigUtils.scopesAsString(spec.getBasicConfig().getScopes()))
        .extraRequestParameters(spec.getBasicConfig().getExtraRequestParameters())
        .resourceOwnerConfig(spec.getResourceOwnerConfig())
        .authorizationCodeConfig(spec.getAuthorizationCodeConfig())
        .deviceCodeConfig(spec.getDeviceCodeConfig())
        .tokenExchangeConfig(spec.getTokenExchangeConfig())
        .runtimeConfig(spec.getRuntimeConfig())
        .build();
  }

  @Nullable
  public static FlowContext createImpersonationFlowContext(
      OAuth2AgentSpec spec, RESTClient restClient) {
    if (!spec.getImpersonationConfig().isEnabled()) {
      return null;
    }
    EndpointProvider endpointProvider =
        EndpointProviderFactory.createImpersonatingEndpointProvider(spec, restClient);
    ClientAuthenticator clientAuthenticator =
        ClientAuthenticatorFactory.createImpersonatingAuthenticator(spec);
    return ImmutableFlowContext.builder()
        .restClient(restClient)
        .endpointProvider(endpointProvider)
        .clientAuthenticator(clientAuthenticator)
        .scopesAsString(ConfigUtils.scopesAsString(spec.getImpersonationConfig().getScopes()))
        .extraRequestParameters(spec.getImpersonationConfig().getExtraRequestParameters())
        .clientId(spec.getImpersonationConfig().getClientId())
        .resourceOwnerConfig(spec.getResourceOwnerConfig())
        .authorizationCodeConfig(spec.getAuthorizationCodeConfig())
        .deviceCodeConfig(spec.getDeviceCodeConfig())
        .tokenExchangeConfig(spec.getTokenExchangeConfig())
        .runtimeConfig(spec.getRuntimeConfig())
        .build();
  }

  @Nullable
  public static FlowContext withRestClient(@Nullable FlowContext context, RESTClient restClient) {
    if (context == null) {
      return null;
    }
    return ImmutableFlowContext.builder()
        .from(context)
        .restClient(restClient)
        .endpointProvider(
            EndpointProvider.builder()
                .from(context.getEndpointProvider())
                .restClient(restClient)
                .build())
        .build();
  }
}

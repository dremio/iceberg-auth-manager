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
package com.dremio.iceberg.authmgr.oauth2.endpoint;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import jakarta.annotation.Nullable;
import org.apache.iceberg.rest.RESTClient;

public final class EndpointProviderFactory {

  private EndpointProviderFactory() {}

  public static EndpointProvider createEndpointProvider(
      OAuth2AgentSpec spec, RESTClient restClient) {
    EndpointProvider.Builder builder = EndpointProvider.builder().restClient(restClient);
    spec.getBasicConfig().getIssuerUrl().ifPresent(builder::issuerUrl);
    spec.getBasicConfig().getTokenEndpoint().ifPresent(builder::tokenEndpoint);
    spec.getAuthorizationCodeConfig()
        .getAuthorizationEndpoint()
        .ifPresent(builder::authorizationEndpoint);
    spec.getDeviceCodeConfig()
        .getDeviceAuthorizationEndpoint()
        .ifPresent(builder::deviceAuthorizationEndpoint);
    return builder.build();
  }

  @Nullable
  public static EndpointProvider createImpersonatingEndpointProvider(
      OAuth2AgentSpec spec, RESTClient restClient) {
    EndpointProvider.Builder builder = EndpointProvider.builder().restClient(restClient);
    spec.getImpersonationConfig().getIssuerUrl().ifPresent(builder::issuerUrl);
    spec.getImpersonationConfig().getTokenEndpoint().ifPresent(builder::tokenEndpoint);
    return builder.build();
  }
}

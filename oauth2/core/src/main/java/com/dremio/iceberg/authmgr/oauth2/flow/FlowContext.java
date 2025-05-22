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

import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticator;
import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.RuntimeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.Map;
import java.util.Optional;
import org.apache.iceberg.rest.RESTClient;

/**
 * An interface representing the context in which an OAuth2 flow is executed. This context provides
 * the necessary components and configurations needed to perform the flow.
 *
 * <p>A flow context is immutable and agent-scoped. It is created from the agent configuration and
 * is passed to the flow when it is created.
 */
@AuthManagerImmutable
public interface FlowContext {

  EndpointProvider getEndpointProvider();

  ClientAuthenticator getClientAuthenticator();

  RESTClient getRestClient();

  Optional<String> getClientId();

  Optional<String> getScopesAsString();

  Map<String, String> getExtraRequestParameters();

  ResourceOwnerConfig getResourceOwnerConfig();

  AuthorizationCodeConfig getAuthorizationCodeConfig();

  DeviceCodeConfig getDeviceCodeConfig();

  TokenExchangeConfig getTokenExchangeConfig();

  RuntimeConfig getRuntimeConfig();
}

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
import org.apache.iceberg.rest.RESTClient;

public class FlowFactory {

  public static Flow forInitialTokenFetch(
      OAuth2AgentSpec config, RESTClient restClient, EndpointResolver endpointResolver) {
    switch (config.getBasicConfig().getGrantType()) {
      case CLIENT_CREDENTIALS:
        switch (config.getBasicConfig().getDialect()) {
          case STANDARD:
            return new ClientCredentialsFlow(config, restClient, endpointResolver);
          case ICEBERG_REST:
            return new IcebergClientCredentialsFlow(config, restClient, endpointResolver);
          default:
            throw new IllegalArgumentException(
                "Unknown or invalid dialect: " + config.getBasicConfig().getDialect());
        }
      case PASSWORD:
        return new PasswordFlow(config, restClient, endpointResolver);
      case AUTHORIZATION_CODE:
        return new AuthorizationCodeFlow(config, restClient, endpointResolver);
      case DEVICE_CODE:
        return new DeviceCodeFlow(config, restClient, endpointResolver);
      case TOKEN_EXCHANGE:
        return new TokenExchangeFlow(config, restClient, endpointResolver);
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid grant type for initial token fetch: "
                + config.getBasicConfig().getGrantType());
    }
  }

  public static Flow forTokenRefresh(
      OAuth2AgentSpec config, RESTClient restClient, EndpointResolver endpointResolver) {
    switch (config.getBasicConfig().getDialect()) {
      case STANDARD:
        return new RefreshTokenFlow(config, restClient, endpointResolver);
      case ICEBERG_REST:
        return new IcebergRefreshTokenFlow(config, restClient, endpointResolver);
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid dialect: " + config.getBasicConfig().getDialect());
    }
  }

  public static Flow forImpersonation(
      OAuth2AgentSpec config, RESTClient restClient, EndpointResolver endpointResolver) {
    return new ImpersonatingTokenExchangeFlow(config, restClient, endpointResolver);
  }
}

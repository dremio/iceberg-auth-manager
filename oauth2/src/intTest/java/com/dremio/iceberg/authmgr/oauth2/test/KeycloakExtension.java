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

package com.dremio.iceberg.authmgr.oauth2.test;

import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.tokenprovider.TokenProviders;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import java.time.Clock;
import org.junit.jupiter.api.extension.ExtensionContext;

public class KeycloakExtension extends TestEnvironmentExtension {

  private KeycloakContainer keycloak;

  @Override
  public void beforeAll(ExtensionContext context) {
    keycloak = new KeycloakContainer();
  }

  @Override
  public void afterAll(ExtensionContext context) {
    if (keycloak != null) {
      keycloak.close();
    }
    keycloak = null;
  }

  @Override
  protected Builder newTestEnvironmentBuilder() {
    return TestEnvironment.builder()
        .unitTest(false)
        .clock(Clock.systemUTC())
        .serverRootUrl(keycloak.getRootUrl())
        .authorizationServerUrl(keycloak.getIssuerUrl())
        .distinctImpersonationServer(false)
        .tokenEndpoint(keycloak.getTokenEndpoint())
        .authorizationEndpoint(keycloak.getAuthEndpoint())
        .deviceAuthorizationEndpoint(keycloak.getDeviceAuthEndpoint())
        .accessTokenLifespan(keycloak.getAccessTokenLifespan())
        .tokenExchangeConfig(
            TokenExchangeConfig.builder()
                .subjectTokenProvider(TokenProviders.CURRENT_ACCESS_TOKEN)
                .build());
  }
}

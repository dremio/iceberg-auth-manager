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
package com.dremio.iceberg.authmgr.oauth2.test.container;

import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProviders;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class KeycloakTestEnvironment extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  @Override
  public void beforeAll(ExtensionContext context) {
    KeycloakContainer keycloak = new KeycloakContainer();
    keycloak.start();
    context
        .getStore(ExtensionContext.Namespace.GLOBAL)
        .put(KeycloakContainer.class.getName(), keycloak);
  }

  @Override
  public void afterAll(ExtensionContext context) {
    KeycloakContainer keycloak =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .remove(KeycloakContainer.class.getName(), KeycloakContainer.class);
    if (keycloak != null) {
      keycloak.close();
    }
  }

  @Override
  protected ImmutableTestEnvironment.Builder newTestEnvironmentBuilder(ExtensionContext context) {
    KeycloakContainer keycloak =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .get(KeycloakContainer.class.getName(), KeycloakContainer.class);
    return TestEnvironment.builder()
        .unitTest(false)
        .clock(Clock.systemUTC())
        .serverRootUrl(keycloak.getRootUrl())
        .authorizationServerUrl(keycloak.getIssuerUrl())
        .impersonationServerUrl(keycloak.getIssuerUrl())
        .tokenEndpoint(keycloak.getTokenEndpoint())
        .impersonationTokenEndpoint(keycloak.getTokenEndpoint())
        .authorizationEndpoint(keycloak.getAuthEndpoint())
        .deviceAuthorizationEndpoint(keycloak.getDeviceAuthEndpoint())
        .accessTokenLifespan(keycloak.getAccessTokenLifespan())
        // must be set to the same values as the main client
        .impersonationClientId(TestConstants.CLIENT_ID1)
        .impersonationClientSecret(TestConstants.CLIENT_SECRET1)
        .impersonationScopes(List.of(TestConstants.SCOPE1))
        .tokenExchangeConfig(
            TokenExchangeConfig.builder()
                .subjectTokenProvider(TokenProviders.CURRENT_ACCESS_TOKEN)
                .build());
  }
}

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
package com.dremio.iceberg.authmgr.oauth2.test.junit;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT;

import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.google.common.base.Strings;
import java.time.Duration;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class KeycloakExtension extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  // Client1 is used for client_secret_basic and client_secret_post authentication
  public static final String CLIENT_ID1 = TestConstants.CLIENT_ID1.getValue();
  public static final String CLIENT_SECRET1 = TestConstants.CLIENT_SECRET1.getValue();
  public static final String CLIENT_AUTH1 = CLIENT_SECRET_BASIC.getValue();

  // Client2 is used for "none" authentication (public client)
  public static final String CLIENT_ID2 = TestConstants.CLIENT_ID2.getValue();
  public static final String CLIENT_AUTH2 = NONE.getValue();

  // Client3 is used for client_secret_jwt authentication
  public static final String CLIENT_ID3 = "Client3";
  public static final String CLIENT_SECRET3 = Strings.repeat("S3CR3T", 10);
  public static final String CLIENT_AUTH3 = CLIENT_SECRET_JWT.getValue();

  // Client4 is used for private_key_jwt authentication (RSA)
  public static final String CLIENT_ID4 = "Client4";
  public static final String CLIENT_SECRET4 = "/openssl/rsa_certificate.pem";
  public static final String CLIENT_AUTH4 = PRIVATE_KEY_JWT.getValue();

  // Client5 is used for private_key_jwt authentication (ECDSA)
  public static final String CLIENT_ID5 = "Client5";
  public static final String CLIENT_SECRET5 = "/openssl/ecdsa_certificate.pem";
  public static final String CLIENT_AUTH5 = PRIVATE_KEY_JWT.getValue();

  public static final String USERNAME = TestConstants.USERNAME;
  public static final String PASSWORD = TestConstants.PASSWORD.getValue();

  public static final String SCOPE1 = TestConstants.SCOPE1.toString();

  public static final Duration ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(15);
  public static final Duration REFRESH_TOKEN_LIFESPAN = Duration.ofSeconds(20);

  @Override
  public void beforeAll(ExtensionContext context) {
    KeycloakContainer keycloak =
        new KeycloakContainer()
            .withScope(SCOPE1)
            .withAccessTokenLifespan(ACCESS_TOKEN_LIFESPAN)
            .withRefreshTokenLifespan(REFRESH_TOKEN_LIFESPAN)
            .withUser(USERNAME, PASSWORD)
            .withClient(CLIENT_ID1, CLIENT_SECRET1, CLIENT_AUTH1)
            .withClient(CLIENT_ID2, null, CLIENT_AUTH2)
            .withClient(CLIENT_ID3, CLIENT_SECRET3, CLIENT_AUTH3)
            .withClient(CLIENT_ID4, CLIENT_SECRET4, CLIENT_AUTH4)
            .withClient(CLIENT_ID5, CLIENT_SECRET5, CLIENT_AUTH5);
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
        .serverRootUrl(keycloak.getRootUrl())
        .authorizationServerUrl(keycloak.getIssuerUrl())
        .tokenEndpoint(keycloak.getTokenEndpoint())
        .authorizationEndpoint(keycloak.getAuthEndpoint())
        .deviceAuthorizationEndpoint(keycloak.getDeviceAuthEndpoint())
        .subjectToken(null) // dynamic by default
        .actorToken(null) // dynamic by default
        // must be set to the same values as the main client
        .subjectClientId(TestConstants.CLIENT_ID1)
        .subjectClientSecret(TestConstants.CLIENT_SECRET1)
        .subjectScope(TestConstants.SCOPE1)
        .actorClientId(TestConstants.CLIENT_ID1)
        .actorClientSecret(TestConstants.CLIENT_SECRET1)
        .actorScope(TestConstants.SCOPE1)
        // Unused
        .audience(null)
        .resource(null);
  }
}

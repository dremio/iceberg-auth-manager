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
package com.dremio.iceberg.authmgr.oauth2.test;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;

public class KeycloakContainer implements AutoCloseable {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakContainer.class);

  private static final Duration ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(15);
  private static final Duration SESSION_LIFESPAN = Duration.ofSeconds(20);

  public static final String CONTEXT_PATH = "/realms/master/";

  private final dasniko.testcontainers.keycloak.KeycloakContainer keycloak;

  private final URI rootUrl;
  private final URI issuerUrl;
  private final URI tokenEndpoint;
  private final URI authEndpoint;
  private final URI deviceAuthEndpoint;

  public KeycloakContainer() {
    keycloak =
        new dasniko.testcontainers.keycloak.KeycloakContainer("keycloak/keycloak:26.0.4")
            .withFeaturesEnabled("preview", "token-exchange")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .withEnv(
                "KC_LOG_LEVEL", getRootLoggerLevel() + ",org.keycloak:" + getKeycloakLoggerLevel());
    keycloak.start();
    rootUrl = URI.create(keycloak.getAuthServerUrl());
    issuerUrl = rootUrl.resolve(CONTEXT_PATH);
    tokenEndpoint = issuerUrl.resolve("protocol/openid-connect/token");
    authEndpoint = issuerUrl.resolve("protocol/openid-connect/auth");
    deviceAuthEndpoint = issuerUrl.resolve("protocol/openid-connect/auth/device");
    try (Keycloak keycloakAdmin = keycloak.getKeycloakAdminClient()) {
      RealmResource master = keycloakAdmin.realms().realm("master");
      updateMasterRealm(master);
      createScope(master);
      createUser(master);
      createClient(master, TestConstants.CLIENT_ID1, true);
      createClient(master, TestConstants.CLIENT_ID2, false);
    }
  }

  @Override
  public void close() {
    keycloak.stop();
  }

  public URI getRootUrl() {
    return rootUrl;
  }

  public URI getIssuerUrl() {
    return issuerUrl;
  }

  public URI getTokenEndpoint() {
    return tokenEndpoint;
  }

  public URI getAuthEndpoint() {
    return authEndpoint;
  }

  public URI getDeviceAuthEndpoint() {
    return deviceAuthEndpoint;
  }

  public Duration getAccessTokenLifespan() {
    return ACCESS_TOKEN_LIFESPAN;
  }

  protected void updateMasterRealm(RealmResource master) {
    RealmRepresentation masterRep = master.toRepresentation();
    masterRep.setAccessTokenLifespan((int) ACCESS_TOKEN_LIFESPAN.toSeconds());
    // Refresh token lifespan will be equal to the smallest value between:
    // SSO Session Idle, SSO Session Max, Client Session Idle, and Client Session Max.
    int sessionLifespanSeconds = (int) SESSION_LIFESPAN.toSeconds();
    masterRep.setClientSessionIdleTimeout(sessionLifespanSeconds);
    masterRep.setClientSessionMaxLifespan(sessionLifespanSeconds);
    masterRep.setSsoSessionIdleTimeout(sessionLifespanSeconds);
    masterRep.setSsoSessionMaxLifespan(sessionLifespanSeconds);
    masterRep.setOAuth2DevicePollingInterval(1);
    master.update(masterRep);
  }

  protected void createScope(RealmResource master) {
    ClientScopeRepresentation scope = new ClientScopeRepresentation();
    scope.setId(UUID.randomUUID().toString());
    scope.setName(TestConstants.SCOPE1);
    scope.setProtocol("openid-connect");
    scope.setAttributes(
        Map.of(
            "include.in.token.scope",
            "true",
            "consent.screen.text",
            "REST Catalog",
            "display.on.consent.screen",
            "true"));
    try (Response response = master.clientScopes().create(scope)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
  }

  protected void createClient(RealmResource master, String clientId, boolean confidential) {
    ClientRepresentation client = new ClientRepresentation();
    client.setId(UUID.randomUUID().toString());
    client.setClientId(clientId);
    client.setPublicClient(!confidential);
    client.setServiceAccountsEnabled(confidential); // required for client credentials grant
    client.setDirectAccessGrantsEnabled(true); // required for password grant
    client.setStandardFlowEnabled(true); // required for authorization code grant
    client.setRedirectUris(ImmutableList.of("http://localhost:*"));
    client.setAttributes(
        ImmutableMap.of(
            "use.refresh.tokens",
            "true",
            "client_credentials.use_refresh_token",
            "false",
            "oauth2.device.authorization.grant.enabled",
            "true"));
    if (confidential) {
      client.setSecret("s3cr3t");
      ResourceServerRepresentation settings = new ResourceServerRepresentation();
      settings.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
      client.setAuthorizationSettings(settings);
    }
    client.setOptionalClientScopes(List.of(TestConstants.SCOPE1));
    try (Response response = master.clients().create(client)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
  }

  protected void createUser(RealmResource master) {
    UserRepresentation user = new UserRepresentation();
    user.setId(UUID.randomUUID().toString());
    user.setUsername(TestConstants.USERNAME);
    user.setFirstName("Alice");
    user.setLastName("Alice");
    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setValue(TestConstants.PASSWORD);
    credential.setTemporary(false);
    user.setCredentials(ImmutableList.of(credential));
    user.setEnabled(true);
    user.setEmail("alice@example.com");
    user.setEmailVerified(true);
    user.setRequiredActions(Collections.emptyList());
    try (Response response = master.users().create(user)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
  }

  private static String getRootLoggerLevel() {
    return LOGGER.isInfoEnabled() ? "INFO" : LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
  }

  private static String getKeycloakLoggerLevel() {
    return LOGGER.isDebugEnabled() ? "DEBUG" : getRootLoggerLevel();
  }
}

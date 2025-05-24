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

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import dasniko.testcontainers.keycloak.ExtendableKeycloakContainer;
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
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;

public class KeycloakContainer extends ExtendableKeycloakContainer<KeycloakContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakContainer.class);

  private static final Duration ACCESS_TOKEN_LIFESPAN = Duration.ofSeconds(15);
  private static final Duration SESSION_LIFESPAN = Duration.ofSeconds(20);

  public static final String CONTEXT_PATH = "/realms/master/";

  private URI rootUrl;
  private URI issuerUrl;
  private URI tokenEndpoint;
  private URI authEndpoint;
  private URI deviceAuthEndpoint;

  @SuppressWarnings("resource")
  public KeycloakContainer() {
    super("keycloak/keycloak:26.0.4");
    withFeaturesEnabled("preview", "token-exchange");
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withEnv("KC_LOG_LEVEL", getRootLoggerLevel() + ",org.keycloak:" + getKeycloakLoggerLevel());
    // Useful when debugging Keycloak REST endpoints:
    withExposedPorts(8080, 9000, 5005)
        .withEnv(
            "JAVA_TOOL_OPTIONS",
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005");
  }

  @Override
  public void start() {
    super.start();
    rootUrl = URI.create(getAuthServerUrl());
    issuerUrl = rootUrl.resolve(CONTEXT_PATH);
    tokenEndpoint = issuerUrl.resolve("protocol/openid-connect/token");
    authEndpoint = issuerUrl.resolve("protocol/openid-connect/auth");
    deviceAuthEndpoint = issuerUrl.resolve("protocol/openid-connect/auth/device");
    try (Keycloak client = getKeycloakAdminClient()) {
      RealmResource master = client.realms().realm("master");
      updateMasterRealm(master);
      createScope(master);
      createUser(master);
      createClient(
          master,
          TestConstants.CLIENT_ID1,
          TestConstants.CLIENT_SECRET1,
          ClientAuthentication.CLIENT_SECRET_BASIC);
      createClient(master, TestConstants.CLIENT_ID2, null, ClientAuthentication.NONE);
    }
  }

  public URI getRootUrl() {
    return rootUrl;
  }

  public URI getIssuerUrl() {
    return issuerUrl;
  }

  public String getIssuerClaim() {
    return removeTrailingSlash(getIssuerUrl().toString());
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

  public String fetchNewToken(String scope) {
    try (Keycloak client =
        Keycloak.getInstance(
            getAuthServerUrl(),
            MASTER_REALM,
            getAdminUsername(),
            getAdminPassword(),
            TestConstants.CLIENT_ID1,
            TestConstants.CLIENT_SECRET1,
            null,
            null,
            false,
            null,
            scope)) {
      return client.tokenManager().getAccessTokenString();
    }
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

  protected void createClient(
      RealmResource master,
      String clientId,
      String clientSecret,
      ClientAuthentication authenticationMethod) {
    ClientRepresentation client = new ClientRepresentation();
    String clientUuid = UUID.randomUUID().toString();
    client.setId(clientUuid);
    client.setClientId(clientId);
    client.setPublicClient(authenticationMethod == ClientAuthentication.NONE);
    client.setServiceAccountsEnabled(
        authenticationMethod != ClientAuthentication.NONE); // required for client credentials grant
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
    if (authenticationMethod != ClientAuthentication.NONE) {
      client.setSecret(clientSecret);
      ResourceServerRepresentation settings = new ResourceServerRepresentation();
      settings.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
      client.setAuthorizationSettings(settings);
    }
    client.setOptionalClientScopes(List.of(TestConstants.SCOPE1));
    try (Response response = master.clients().create(client)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
    addPrincipalIdClaimMapper(master, clientUuid);
    addPrincipalRoleClaimMapper(master, clientUuid);
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

  private void addPrincipalIdClaimMapper(RealmResource master, String clientUuid) {
    ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setId(UUID.randomUUID().toString());
    mapper.setName("principal-id-claim-mapper");
    mapper.setProtocol("openid-connect");
    mapper.setProtocolMapper("oidc-hardcoded-claim-mapper");
    mapper.setConfig(
        ImmutableMap.<String, String>builder()
            .put("claim.name", "principal_id")
            .put("claim.value", "1")
            .put("jsonType.label", "long")
            .put("id.token.claim", "true")
            .put("access.token.claim", "true")
            .put("userinfo.token.claim", "true")
            .build());
    try (Response response =
        master.clients().get(clientUuid).getProtocolMappers().createMapper(mapper)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
  }

  private void addPrincipalRoleClaimMapper(RealmResource master, String clientUuid) {
    ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setId(UUID.randomUUID().toString());
    mapper.setName("principal-role-claim-mapper");
    mapper.setProtocol("openid-connect");
    mapper.setProtocolMapper("oidc-hardcoded-claim-mapper");
    mapper.setConfig(
        ImmutableMap.<String, String>builder()
            .put("claim.name", "groups")
            .put("claim.value", "[\"PRINCIPAL_ROLE:ALL\"]")
            .put("jsonType.label", "JSON")
            .put("id.token.claim", "true")
            .put("access.token.claim", "true")
            .put("userinfo.token.claim", "true")
            .build());
    try (Response response =
        master.clients().get(clientUuid).getProtocolMappers().createMapper(mapper)) {
      assertThat(response.getStatus()).isEqualTo(201);
    }
  }

  private static String getRootLoggerLevel() {
    return LOGGER.isInfoEnabled() ? "INFO" : LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
  }

  private static String getKeycloakLoggerLevel() {
    return LOGGER.isDebugEnabled() ? "DEBUG" : getRootLoggerLevel();
  }

  private static String removeTrailingSlash(String url) {
    return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
  }
}

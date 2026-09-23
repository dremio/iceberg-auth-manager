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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import dasniko.testcontainers.keycloak.ExtendableKeycloakContainer;
import dasniko.testcontainers.keycloak.HttpsClientAuth;
import jakarta.annotation.Nullable;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

public class KeycloakContainer extends ExtendableKeycloakContainer<KeycloakContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakContainer.class);

  private static final String CONTEXT_PATH = "/realms/master/";

  protected record FederatedIdentity(
      String username, String providerAlias, String externalUserId, String externalUsername) {}

  private final List<ClientScopeRepresentation> scopes = new ArrayList<>();
  private final List<ClientRepresentation> clients = new ArrayList<>();
  private final List<IdentityProviderRepresentation> identityProviders = new ArrayList<>();
  private final List<FederatedIdentity> federatedIdentities = new ArrayList<>();
  private final List<String> providerAliases = new ArrayList<>();
  private final List<UserRepresentation> users = new ArrayList<>();

  private Duration accessTokenLifespan = Duration.ofMinutes(10);
  private Duration refreshTokenLifespan = Duration.ofHours(1);

  private URI rootUrl;
  private URI issuerUrl;
  private URI tokenEndpoint;
  private URI authEndpoint;
  private URI deviceAuthEndpoint;

  @SuppressWarnings("resource")
  public KeycloakContainer() {
    super("keycloak/keycloak:26.7.4-0");
    withNetworkAliases("keycloak");
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withEnv("KC_LOG_LEVEL", getRootLoggerLevel() + ",org.keycloak:" + getKeycloakLoggerLevel());
    // DPoP is still a preview feature in Keycloak 26.x and must be enabled explicitly. mTLS
    // client authentication (RFC 8705) uses Keycloak's built-in client-x509 authenticator and is
    // available without an explicit feature flag.
    withFeaturesEnabled("dpop");
    // Useful when debugging Keycloak REST endpoints:
    addExposedPorts(5005);
    withEnv(
        "JAVA_TOOL_OPTIONS",
        "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005");
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withScope(String scope) {
    scopes.add(newScope(scope));
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withClient(
      String clientId, String clientSecret, String authenticationMethod) {
    return withClient(clientId, clientSecret, authenticationMethod, false);
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withClient(
      String clientId, String clientSecret, String authenticationMethod, boolean dpopBound) {
    clients.add(newClient(clientId, clientSecret, authenticationMethod, dpopBound));
    return this;
  }

  /**
   * Registers a client that authenticates at the token endpoint with a TLS client certificate (RFC
   * 8705 §2). {@code certBase64} is the DER-encoded certificate without PEM headers, as returned by
   * {@code TestCertificates#getRsaCertificateBase64()}. When {@code certBound} is true, the issued
   * access token will carry a {@code cnf.x5t#S256} confirmation claim binding it to the cert (RFC
   * 8705 §3).
   */
  @CanIgnoreReturnValue
  public KeycloakContainer withMtlsClient(
      String clientId, String authenticationMethod, String certBase64, boolean certBound) {
    clients.add(newMtlsClient(clientId, authenticationMethod, certBase64, certBound));
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withUser(String username, String password) {
    users.add(newUser(username, password));
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withIdentityProvider(String alias, String issuer, Path publicKeyPem) {
    identityProviders.add(newIdentityProvider(alias, issuer, publicKeyPem));
    providerAliases.add(alias);
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withFederatedIdentity(
      String username, String providerAlias, String externalUserId, String externalUsername) {
    federatedIdentities.add(
        new FederatedIdentity(username, providerAlias, externalUserId, externalUsername));
    return this;
  }

  /**
   * Enables HTTPS termination on the Keycloak container (using the dasniko-bundled server cert),
   * requests a client certificate during the TLS handshake, and (if {@code clientCertPath} is
   * provided) adds it to Keycloak's truststore so the handshake completes. The actual client
   * identity check is delegated to the Keycloak client's X.509 authenticator (see {@link
   * #withMtlsClient}).
   *
   * <p>{@code HttpsClientAuth.REQUEST} (rather than {@code REQUIRED}) is used so that connections
   * without a client cert (e.g. health probes) still succeed; when a cert is presented, Keycloak
   * validates it against the configured truststore.
   *
   * <p>{@code clientCertPath} is a host-side path to a PEM-encoded X.509 certificate (e.g. the one
   * produced by {@code TestCertificates#getRsaCertificatePem()}). It is copied into the container
   * and registered via the Keycloak 26 {@code --truststore-paths} option (env var {@code
   * KC_TRUSTSTORE_PATHS}), which accepts PEM files directly.
   */
  @CanIgnoreReturnValue
  public KeycloakContainer withMutualTls(@Nullable Path clientCertPath) {
    useTls();
    withHttpsClientAuth(HttpsClientAuth.REQUEST);
    if (clientCertPath != null) {
      String inContainer = "/opt/keycloak/conf/authmgr-client-ca.pem";
      withCopyFileToContainer(
          MountableFile.forHostPath(clientCertPath.toAbsolutePath()), inContainer);
      withEnv("KC_TRUSTSTORE_PATHS", inContainer);
    }
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withAccessTokenLifespan(Duration accessTokenLifespan) {
    this.accessTokenLifespan = accessTokenLifespan;
    return this;
  }

  @CanIgnoreReturnValue
  public KeycloakContainer withRefreshTokenLifespan(Duration refreshTokenLifespan) {
    this.refreshTokenLifespan = refreshTokenLifespan;
    return this;
  }

  @Override
  public void start() {
    if (getContainerId() != null) {
      return;
    }
    super.start();
    rootUrl = URI.create(getAuthServerUrl());
    issuerUrl = rootUrl.resolve(CONTEXT_PATH);
    tokenEndpoint = issuerUrl.resolve("protocol/openid-connect/token");
    authEndpoint = issuerUrl.resolve("protocol/openid-connect/auth");
    deviceAuthEndpoint = issuerUrl.resolve("protocol/openid-connect/auth/device");
    try (Keycloak client = getKeycloakAdminClient()) {
      RealmResource master = client.realms().realm("master");
      updateMasterRealm(master);
      scopes.forEach(scope -> createScope(master, scope));
      identityProviders.forEach(
          identityProvider -> createIdentityProvider(master, identityProvider));
      users.forEach(user -> createUser(master, user));
      clients.forEach(cl -> createClient(master, cl));
      federatedIdentities.forEach(link -> createFederatedIdentityLink(master, link));
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

  public String fetchNewToken(String clientId, String clientSecret, String scope) {
    try (Keycloak client =
        Keycloak.getInstance(
            getAuthServerUrl(),
            MASTER_REALM,
            getAdminUsername(),
            getAdminPassword(),
            clientId,
            clientSecret,
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
    masterRep.setAccessTokenLifespan((int) accessTokenLifespan.toSeconds());
    // Refresh token lifespan will be equal to the smallest value between:
    // SSO Session Idle, SSO Session Max, Client Session Idle, and Client Session Max.
    int sessionLifespanSeconds = (int) refreshTokenLifespan.toSeconds();
    masterRep.setClientSessionIdleTimeout(sessionLifespanSeconds);
    masterRep.setClientSessionMaxLifespan(sessionLifespanSeconds);
    masterRep.setSsoSessionIdleTimeout(sessionLifespanSeconds);
    masterRep.setSsoSessionMaxLifespan(sessionLifespanSeconds);
    // Minimum polling interval for device auth flow
    masterRep.setOAuth2DevicePollingInterval(1);
    master.update(masterRep);
  }

  protected void createScope(RealmResource master, ClientScopeRepresentation scope) {
    try (Response response = master.clientScopes().create(scope)) {
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create scope: " + response.readEntity(String.class));
      }
    }
  }

  protected void createClient(RealmResource master, ClientRepresentation client) {
    if (!client.isPublicClient() && !providerAliases.isEmpty()) {
      Map<String, String> attributes =
          client.getAttributes() == null ? new HashMap<>() : new HashMap<>(client.getAttributes());
      attributes.put("oauth2.jwt.authorization.grant.enabled", "true");
      String keycloakMultiValueDelimiter = "##";
      attributes.put(
          "oauth2.jwt.authorization.grant.idp",
          String.join(keycloakMultiValueDelimiter, providerAliases));
      client.setAttributes(attributes);
    }
    client.setOptionalClientScopes(
        ImmutableList.<String>builder()
            .addAll(scopes.stream().map(ClientScopeRepresentation::getName).iterator())
            .add("offline_access")
            .build());
    try (Response response = master.clients().create(client)) {
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create client: " + response.readEntity(String.class));
      }
    }
    // Required for Polaris
    addPrincipalIdClaimMapper(master, client.getId());
    addPrincipalRoleClaimMapper(master, client.getId());
  }

  protected void createIdentityProvider(
      RealmResource master, IdentityProviderRepresentation identityProvider) {
    try (Response response = master.identityProviders().create(identityProvider)) {
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create identity provider: " + response.readEntity(String.class));
      }
    }
  }

  protected void createUser(RealmResource master, UserRepresentation user) {
    try (Response response = master.users().create(user)) {
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create user: " + response.readEntity(String.class));
      }
    }
  }

  protected void createFederatedIdentityLink(RealmResource master, FederatedIdentity link) {
    String userId =
        master.users().searchByUsername(link.username(), true).stream()
            .findFirst()
            .map(UserRepresentation::getId)
            .orElseThrow(
                () ->
                    new IllegalStateException(
                        "Failed to find user for federated identity link: " + link.username()));
    FederatedIdentityRepresentation rep = new FederatedIdentityRepresentation();
    rep.setIdentityProvider(link.providerAlias());
    rep.setUserId(link.externalUserId());
    rep.setUserName(link.externalUsername());
    try (Response response =
        master.users().get(userId).addFederatedIdentity(link.providerAlias(), rep)) {
      if (response.getStatus() != 204) {
        throw new IllegalStateException(
            "Failed to create federated identity link: " + response.readEntity(String.class));
      }
    }
  }

  private static ClientScopeRepresentation newScope(String scopeName) {
    ClientScopeRepresentation scope = new ClientScopeRepresentation();
    scope.setId(UUID.randomUUID().toString());
    scope.setName(scopeName);
    scope.setProtocol("openid-connect");
    scope.setAttributes(
        Map.of(
            "include.in.token.scope",
            "true",
            "consent.screen.text",
            "REST Catalog",
            "display.on.consent.screen",
            "true"));
    return scope;
  }

  private static ClientRepresentation newClient(
      String clientId, String clientSecret, String authenticationMethod, boolean dpopBound) {
    ClientRepresentation client = new ClientRepresentation();
    String clientUuid = UUID.randomUUID().toString();
    client.setId(clientUuid);
    client.setClientId(clientId);
    boolean publicClient = authenticationMethod.equals("none");
    client.setPublicClient(publicClient);
    client.setServiceAccountsEnabled(!publicClient); // required for client credentials grant
    client.setDirectAccessGrantsEnabled(true); // required for password grant
    client.setStandardFlowEnabled(true); // required for authorization code grant
    client.setRedirectUris(List.of("http://localhost:*", "https://localhost:*"));
    ImmutableMap.Builder<String, String> attributes =
        ImmutableMap.<String, String>builder()
            .put("use.refresh.tokens", "true")
            .put("client_credentials.use_refresh_token", "false")
            .put("oauth2.device.authorization.grant.enabled", "true")
            .put("standard.token.exchange.enabled", "true")
            .put("standard.token.exchange.enableRefreshRequestedTokenType", "SAME_SESSION");
    if (dpopBound) {
      attributes.put("dpop.bound.access.tokens", "true");
    }
    switch (authenticationMethod) {
      case "client_secret_basic":
      case "client_secret_post":
        client.setSecret(clientSecret);
        break;
      case "client_secret_jwt":
        client.setSecret(clientSecret);
        client.setClientAuthenticatorType("client-secret-jwt");
        break;
      case "private_key_jwt":
        // clientSecret is expected to be the base64-encoded certificate (no PEM headers)
        attributes.put("jwt.credential.certificate", clientSecret);
        client.setClientAuthenticatorType("client-jwt");
        break;
    }
    if (!publicClient) {
      ResourceServerRepresentation settings = new ResourceServerRepresentation();
      settings.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
      client.setAuthorizationSettings(settings);
    }
    client.setAttributes(attributes.build());
    return client;
  }

  private static ClientRepresentation newMtlsClient(
      String clientId, String authenticationMethod, String certBase64, boolean certBound) {
    ClientRepresentation client = new ClientRepresentation();
    client.setId(UUID.randomUUID().toString());
    client.setClientId(clientId);
    client.setPublicClient(false);
    client.setServiceAccountsEnabled(true);
    client.setDirectAccessGrantsEnabled(true);
    client.setStandardFlowEnabled(true);
    client.setRedirectUris(List.of("http://localhost:*", "https://localhost:*"));
    // Keycloak uses a single X.509 authenticator with a "method-discriminator" attribute to
    // distinguish PKI-validated (`tls_client_auth`) from self-signed
    // (`self_signed_tls_client_auth`) mTLS flavors. The authenticator id is "client-x509".
    client.setClientAuthenticatorType("client-x509");
    ImmutableMap.Builder<String, String> attributes =
        ImmutableMap.<String, String>builder()
            .put("use.refresh.tokens", "true")
            .put("client_credentials.use_refresh_token", "false")
            .put("oauth2.device.authorization.grant.enabled", "true")
            .put("tls.client.certificate.bound.access.tokens", String.valueOf(certBound))
            .put("x509.subjectdn", ".*")
            .put("x509.allow.regex.pattern.comparison", "true");
    if (authenticationMethod.equals("self_signed_tls_client_auth")) {
      attributes.put("x509.use.self.signed.certificate", "true");
      attributes.put("jwt.credential.certificate", certBase64);
    }
    client.setAttributes(attributes.build());
    return client;
  }

  private static IdentityProviderRepresentation newIdentityProvider(
      String alias, String issuer, Path publicKeyPem) {
    IdentityProviderRepresentation identityProvider = new IdentityProviderRepresentation();
    identityProvider.setAlias(alias);
    identityProvider.setProviderId("jwt-authorization-grant");
    identityProvider.setDisplayName(alias);
    identityProvider.setEnabled(true);
    identityProvider.setHideOnLogin(true);
    String publicKeyPemEncoded;
    try {
      publicKeyPemEncoded = Files.readString(publicKeyPem);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    identityProvider.setConfig(
        ImmutableMap.<String, String>builder()
            .put("issuer", issuer)
            .put("useJwksUrl", "false")
            .put("jwtAuthorizationGrantEnabled", "true")
            .put("jwtAuthorizationGrantAssertionReuseAllowed", "true")
            .put("jwtAuthorizationGrantAllowedClockSkew", "30")
            .put("publicKeySignatureVerifier", publicKeyPemEncoded)
            .build());
    return identityProvider;
  }

  private static UserRepresentation newUser(String username, String password) {
    UserRepresentation user = new UserRepresentation();
    user.setId(UUID.randomUUID().toString());
    user.setUsername(username);
    user.setFirstName(username);
    user.setLastName(username);
    CredentialRepresentation credential = new CredentialRepresentation();
    credential.setType(CredentialRepresentation.PASSWORD);
    credential.setValue(password);
    credential.setTemporary(false);
    user.setCredentials(ImmutableList.of(credential));
    user.setEnabled(true);
    user.setEmail(username.toLowerCase(Locale.ROOT) + "@example.com");
    user.setEmailVerified(true);
    user.setRequiredActions(Collections.emptyList());
    return user;
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
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create mapper: " + response.readEntity(String.class));
      }
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
      if (response.getStatus() != 201) {
        throw new IllegalStateException(
            "Failed to create role claim mapper: " + response.readEntity(String.class));
      }
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

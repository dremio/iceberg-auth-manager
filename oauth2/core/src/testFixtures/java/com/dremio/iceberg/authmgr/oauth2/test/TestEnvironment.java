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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.USERNAME;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Runtime;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.RuntimeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProviderFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableAuthorizationCodeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableClientCredentialsExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableConfigEndpointExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableDeviceCodeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableErrorExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableIcebergClientCredentialsExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableIcebergRefreshTokenExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableLoadTableEndpointExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableMetadataDiscoveryExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutablePasswordExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableRefreshTokenExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableTokenExchangeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.server.HttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.server.IntegrationTestHttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.server.UnitTestHttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.user.InteractiveUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakAuthCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakDeviceCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserEmulator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.RESTCatalog;
import org.apache.iceberg.rest.ResourcePaths;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.util.ThreadPools;
import org.immutables.value.Value;

@AuthManagerImmutable
@Value.Immutable(copy = false)
public abstract class TestEnvironment implements AutoCloseable {

  public static Builder builder() {
    return ImmutableTestEnvironment.builder();
  }

  @Value.Check
  public void validate() {
    Preconditions.checkArgument(getGrantType().isInitial(), "Grant type must be initial");
    getServer();
    getHttpClient();
    getUser();
    if (isCreateDefaultExpectations()) {
      createExpectations();
    }
  }

  @Value.Default
  public GrantType getGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public Dialect getDialect() {
    return Dialect.STANDARD;
  }

  @Value.Default
  public boolean isUnitTest() {
    return true;
  }

  @Value.Default
  public boolean isPrivateClient() {
    return true;
  }

  @Value.Default
  public boolean isDiscoveryEnabled() {
    return true;
  }

  @Value.Default
  public boolean isReturnRefreshTokens() {
    return true;
  }

  @Value.Default
  public boolean isIncludeDeviceAuthEndpointInDiscoveryMetadata() {
    return true;
  }

  @Value.Default
  public boolean isCreateDefaultExpectations() {
    return isUnitTest();
  }

  @Value.Lazy
  public HttpServer getServer() {
    return isUnitTest() ? new UnitTestHttpServer() : new IntegrationTestHttpServer();
  }

  @Value.Default
  public HTTPClient getHttpClient() {
    return newHttpClientBuilder(Map.of()).build();
  }

  public HTTPClient.Builder newHttpClientBuilder(Map<String, String> properties) {
    return HTTPClient.builder(properties)
        .uri(getCatalogServerUrl())
        .withAuthSession(AuthSession.EMPTY);
  }

  @Value.Default
  public ScheduledExecutorService getExecutor() {
    return ThreadPools.newScheduledPool(getAgentName() + "-refresh", 1);
  }

  @Value.Lazy
  public EndpointProvider getEndpointProvider() {
    return EndpointProviderFactory.createEndpointProvider(getAgentSpec(), this::getHttpClient);
  }

  public void reset() {
    getServer().reset();
  }

  @Override
  public void close() {
    getUser().close();
    try {
      getHttpClient().close();
    } catch (IOException ignored) {
    }
    try {
      getExecutor().shutdown();
      if (!getExecutor().awaitTermination(10, TimeUnit.SECONDS)) {
        getExecutor().shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    getServer().close();
  }

  @Value.Default
  public URI getServerRootUrl() {
    // Note: the default value is for unit tests; integration tests must provide the server root URL
    // to avoid circular dependencies when creating the TestEnvironment instance
    return getServer().getRootUrl();
  }

  @Value.Default
  public String getAuthorizationServerContextPath() {
    return "/realms/master/";
  }

  @Value.Default
  public String getCatalogServerContextPath() {
    return "/api/catalog/";
  }

  @Value.Default
  public URI getAuthorizationServerUrl() {
    return getServerRootUrl().resolve(getAuthorizationServerContextPath());
  }

  @Value.Default
  public URI getCatalogServerUrl() {
    return getServerRootUrl().resolve(getCatalogServerContextPath());
  }

  @Value.Default
  public URI getTokenEndpoint() {
    return getAuthorizationServerUrl().resolve("protocol/openid-connect/token");
  }

  @Value.Default
  public URI getAuthorizationEndpoint() {
    return getAuthorizationServerUrl().resolve("protocol/openid-connect/auth");
  }

  @Value.Default
  public URI getDeviceAuthorizationEndpoint() {
    return getAuthorizationServerUrl().resolve("protocol/openid-connect/device-auth");
  }

  @Value.Default
  public URI getDeviceVerificationEndpoint() {
    return getAuthorizationServerUrl().resolve("device");
  }

  @Value.Default
  public URI getConfigEndpoint() {
    return getCatalogServerUrl().resolve(ResourcePaths.config());
  }

  @Value.Default
  public URI getLoadTableEndpoint() {
    return getCatalogServerUrl()
        .resolve(
            ResourcePaths.forCatalogProperties(getCatalogProperties())
                .table(TestConstants.TABLE_IDENTIFIER));
  }

  @Value.Default
  public String getWellKnownPath() {
    return EndpointProvider.WELL_KNOWN_PATHS.get(0);
  }

  @Value.Default
  public URI getDiscoveryEndpoint() {
    return getAuthorizationServerUrl().resolve(getWellKnownPath());
  }

  @Value.Default
  public OAuth2AgentSpec getAgentSpec() {
    return OAuth2AgentSpec.builder()
        .basicConfig(getBasicConfig())
        .resourceOwnerConfig(getResourceOwnerConfig())
        .authorizationCodeConfig(getAuthorizationCodeConfig())
        .deviceCodeConfig(getDeviceCodeConfig())
        .tokenRefreshConfig(getTokenRefreshConfig())
        .tokenExchangeConfig(getTokenExchangeConfig())
        .clientAssertionConfig(getClientAssertionConfig())
        .runtimeConfig(getRuntimeConfig())
        .build();
  }

  @Value.Default
  public BasicConfig getBasicConfig() {
    BasicConfig.Builder builder =
        BasicConfig.builder()
            .scopes(getScopes())
            .extraRequestParameters(Map.of("extra1", "value1"))
            .grantType(getGrantType())
            .dialect(getDialect())
            .minTimeout(getTimeout())
            .timeout(getTimeout());
    if (getToken().isPresent()) {
      builder.token(getToken().get());
    } else {
      builder.clientId(getClientId());
      if (isPrivateClient()) {
        builder.clientSecret(getClientSecret());
      }
      builder.clientId(getClientId());
    }
    getClientAuthentication().ifPresent(builder::clientAuthentication);
    if (isDiscoveryEnabled()) {
      builder.issuerUrl(getAuthorizationServerUrl());
    } else {
      builder.tokenEndpoint(getTokenEndpoint());
    }
    return builder.build();
  }

  @Value.Default
  public String getClientId() {
    return TestConstants.CLIENT_ID1;
  }

  @Value.Default
  public String getClientSecret() {
    return TestConstants.CLIENT_SECRET1;
  }

  public abstract Optional<ClientAuthentication> getClientAuthentication();

  public abstract Optional<String> getToken();

  @Value.Default
  public List<String> getScopes() {
    return List.of(TestConstants.SCOPE1);
  }

  @Value.Default
  public Duration getTimeout() {
    return Duration.ofSeconds(5);
  }

  @Value.Default
  public TokenRefreshConfig getTokenRefreshConfig() {
    return TokenRefreshConfig.builder()
        .enabled(isTokenRefreshEnabled())
        .accessTokenLifespan(getAccessTokenLifespan())
        .minAccessTokenLifespan(getAccessTokenLifespan())
        // safety window and idle timeout are tailored for integration tests
        .safetyWindow(Duration.ofSeconds(5))
        .minRefreshDelay(Duration.ofSeconds(5))
        .idleTimeout(Duration.ofSeconds(5))
        .minIdleTimeout(Duration.ofSeconds(5))
        .build();
  }

  @Value.Default
  public boolean isTokenRefreshEnabled() {
    return true;
  }

  @Value.Default
  public Duration getAccessTokenLifespan() {
    return TestConstants.ACCESS_TOKEN_LIFESPAN;
  }

  @Value.Default
  public Duration getRefreshTokenLifespan() {
    return TestConstants.REFRESH_TOKEN_LIFESPAN;
  }

  @Value.Default
  public ResourceOwnerConfig getResourceOwnerConfig() {
    return ResourceOwnerConfig.builder()
        .username(TestConstants.USERNAME)
        .password(getPassword())
        .build();
  }

  @Value.Default
  public String getPassword() {
    return TestConstants.PASSWORD;
  }

  @Value.Default
  public AuthorizationCodeConfig getAuthorizationCodeConfig() {
    AuthorizationCodeConfig.Builder builder =
        AuthorizationCodeConfig.builder()
            .pkceEnabled(isPkceEnabled())
            .pkceTransformation(getPkceTransformation());
    if (!isDiscoveryEnabled()) {
      builder.authorizationEndpoint(getAuthorizationEndpoint());
    }
    return builder.build();
  }

  @Value.Default
  public boolean isPkceEnabled() {
    return true;
  }

  @Value.Default
  public PkceTransformation getPkceTransformation() {
    return PkceTransformation.S256;
  }

  @Value.Default
  public DeviceCodeConfig getDeviceCodeConfig() {
    DeviceCodeConfig.Builder builder =
        DeviceCodeConfig.builder()
            .ignoreServerPollInterval(isUnitTest())
            .minPollInterval(Duration.ofMillis(10))
            .pollInterval(Duration.ofMillis(10));
    if (!isDiscoveryEnabled()) {
      builder.deviceAuthorizationEndpoint(getDeviceAuthorizationEndpoint());
    }
    return builder.build();
  }

  @Value.Default
  public TokenExchangeConfig getTokenExchangeConfig() {
    TokenExchangeConfig.Builder builder =
        TokenExchangeConfig.builder()
            .subjectTokenType(getSubjectTokenType())
            .actorTokenType(getActorTokenType())
            .subjectTokenConfig(getSubjectTokenConfig())
            .actorTokenConfig(getActorTokenConfig())
            .requestedTokenType(getRequestedTokenType());
    if (getSubjectToken() != null) {
      builder.subjectToken(getSubjectToken());
    }
    if (getActorToken() != null) {
      builder.actorToken(getActorToken());
    }
    if (getAudience() != null) {
      builder.audience(getAudience());
    }
    if (getResource() != null) {
      builder.resource(getResource());
    }
    return builder.build();
  }

  @Value.Default
  @Nullable
  public String getSubjectToken() {
    return TestConstants.SUBJECT_TOKEN;
  }

  @Value.Default
  public URI getSubjectTokenType() {
    return TestConstants.SUBJECT_TOKEN_TYPE;
  }

  @Value.Default
  public GrantType getSubjectGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public String getSubjectClientId() {
    return TestConstants.CLIENT_ID2;
  }

  @Value.Default
  public String getSubjectClientSecret() {
    return TestConstants.CLIENT_SECRET2;
  }

  @Value.Default
  public List<String> getSubjectScopes() {
    return List.of(TestConstants.SCOPE2);
  }

  @Value.Default
  public Map<String, String> getSubjectTokenConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(Basic.GRANT_TYPE, getSubjectGrantType().getCommonName())
            .put(Basic.CLIENT_ID, getSubjectClientId())
            .put(Basic.CLIENT_SECRET, getSubjectClientSecret())
            .put(Basic.EXTRA_PARAMS_PREFIX + "extra2", "value2");
    ConfigUtils.scopesAsString(getSubjectScopes())
        .ifPresent(scope -> builder.put(Basic.SCOPE, scope));
    return builder.build();
  }

  @Value.Default
  @Nullable
  public String getActorToken() {
    return TestConstants.ACTOR_TOKEN;
  }

  @Value.Default
  public URI getActorTokenType() {
    return TestConstants.ACTOR_TOKEN_TYPE;
  }

  @Value.Default
  public GrantType getActorGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public String getActorClientId() {
    return TestConstants.CLIENT_ID1;
  }

  @Value.Default
  public String getActorClientSecret() {
    return TestConstants.CLIENT_SECRET1;
  }

  @Value.Default
  public List<String> getActorScopes() {
    return List.of(TestConstants.SCOPE1);
  }

  @Value.Default
  public Map<String, String> getActorTokenConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(Basic.GRANT_TYPE, getActorGrantType().getCommonName())
            .put(Basic.CLIENT_ID, getActorClientId())
            .put(Basic.CLIENT_SECRET, getActorClientSecret())
            .put(Basic.EXTRA_PARAMS_PREFIX + "extra2", "value2");
    ConfigUtils.scopesAsString(getActorScopes())
        .ifPresent(scope -> builder.put(Basic.SCOPE, scope));
    return builder.build();
  }

  @Value.Default
  public URI getRequestedTokenType() {
    return TestConstants.REQUESTED_TOKEN_TYPE;
  }

  @Value.Default
  @Nullable
  public String getAudience() {
    return TestConstants.AUDIENCE;
  }

  @Value.Default
  @Nullable
  public URI getResource() {
    return TestConstants.RESOURCE;
  }

  @Value.Default
  public ClientAssertionConfig getClientAssertionConfig() {
    return ClientAssertionConfig.DEFAULT;
  }

  @Value.Default
  public RuntimeConfig getRuntimeConfig() {
    RuntimeConfig.Builder builder =
        RuntimeConfig.builder().clock(getClock()).agentName(getAgentName()).console(getConsole());
    return builder.build();
  }

  @Value.Default
  public Clock getClock() {
    return new TestClock(TestConstants.NOW);
  }

  @Value.Default
  public String getAgentName() {
    return "iceberg-auth-manager-" + FlowUtils.randomAlphaNumString(4);
  }

  @Value.Derived
  public PrintStream getConsole() {
    return getUser().getConsole();
  }

  @Value.Default
  public boolean isForceInactiveUser() {
    return false;
  }

  @Value.Default
  public UserEmulator getUser() {
    if (isForceInactiveUser()) {
      return UserEmulator.INACTIVE;
    } else {
      GrantType mainGrant = getBasicConfig().getGrantType();
      GrantType subjectGrant =
          mainGrant == GrantType.TOKEN_EXCHANGE
                  && getTokenExchangeConfig().getSubjectToken().isEmpty()
                  && getTokenExchangeConfig().getSubjectTokenConfig().containsKey(Basic.GRANT_TYPE)
              ? GrantType.fromConfigName(
                  getTokenExchangeConfig().getSubjectTokenConfig().get(Basic.GRANT_TYPE))
              : null;
      GrantType actorGrant =
          mainGrant == GrantType.TOKEN_EXCHANGE
                  && getTokenExchangeConfig().getActorToken().isEmpty()
                  && getTokenExchangeConfig().getActorTokenConfig().containsKey(Basic.GRANT_TYPE)
              ? GrantType.fromConfigName(
                  getTokenExchangeConfig().getActorTokenConfig().get(Basic.GRANT_TYPE))
              : null;
      if (mainGrant == GrantType.AUTHORIZATION_CODE
          || subjectGrant == GrantType.AUTHORIZATION_CODE
          || actorGrant == GrantType.AUTHORIZATION_CODE) {
        return isUnitTest()
            ? new KeycloakAuthCodeUserEmulator()
            : new KeycloakAuthCodeUserEmulator(USERNAME, PASSWORD);
      } else if (mainGrant == GrantType.DEVICE_CODE
          || subjectGrant == GrantType.DEVICE_CODE
          || actorGrant == GrantType.DEVICE_CODE) {
        return isUnitTest()
            ? new KeycloakDeviceCodeUserEmulator()
            : new KeycloakDeviceCodeUserEmulator(USERNAME, PASSWORD);
      }
    }
    return UserEmulator.INACTIVE;
  }

  @Value.Default
  public Map<String, String> getCatalogProperties() {
    return ImmutableMap.<String, String>builder()
        .put(CatalogProperties.URI, getCatalogServerUrl().toString())
        .put("prefix", TestConstants.WAREHOUSE)
        .put(CatalogProperties.FILE_IO_IMPL, "org.apache.iceberg.inmemory.InMemoryFileIO")
        .put(AuthProperties.AUTH_TYPE, OAuth2Manager.class.getName())
        .put(Basic.GRANT_TYPE, getGrantType().toString())
        .put(Basic.ISSUER_URL, getAuthorizationServerUrl().toString())
        .put(Basic.CLIENT_ID, getClientId())
        .put(Basic.CLIENT_SECRET, getClientSecret())
        .put(Basic.SCOPE, ConfigUtils.scopesAsString(getScopes()).orElse(TestConstants.SCOPE1))
        .put(Basic.DIALECT, getDialect().toString())
        .put(Basic.EXTRA_PARAMS_PREFIX + "extra1", "value1")
        .put(Runtime.AGENT_NAME, getAgentName())
        .build();
  }

  @Value.Default
  public SessionContext getSessionContext() {
    return SessionContext.createEmpty();
  }

  @Value.Default
  public Map<String, String> getTableProperties() {
    return Map.of();
  }

  public RESTCatalog newCatalog() {
    RESTCatalog catalog =
        new RESTCatalog(getSessionContext(), config -> newHttpClientBuilder(config).build());
    UserEmulator user = getUser();
    if (user instanceof InteractiveUserEmulator) {
      // when testing a RESTCatalog, we need to replace system out
      // since we don't have access to the RuntimeConfig
      ((InteractiveUserEmulator) user).replaceSystemOut();
    }
    user.setErrorListener(
        e -> {
          try {
            catalog.close();
          } catch (IOException ex) {
            throw new RuntimeException(ex);
          }
        });
    catalog.initialize("catalog-" + FlowUtils.randomAlphaNumString(4), getCatalogProperties());
    return catalog;
  }

  public FlowFactory newFlowFactory() {
    return FlowFactory.of(getAgentSpec(), getExecutor(), this::getHttpClient);
  }

  public OAuth2Agent newAgent() {
    OAuth2Agent agent = new OAuth2Agent(getAgentSpec(), getExecutor(), this::getHttpClient);
    getUser().setErrorListener(e -> agent.close());
    return agent;
  }

  public void createExpectations() {
    if (getDialect() == Dialect.STANDARD) {
      ImmutableClientCredentialsExpectation.of(this).create();
    } else {
      ImmutableIcebergClientCredentialsExpectation.of(this).create();
    }
    ImmutablePasswordExpectation.of(this).create();
    ImmutableAuthorizationCodeExpectation.of(this).create();
    ImmutableDeviceCodeExpectation.of(this).create();
    ImmutableTokenExchangeExpectation.of(this).create();
    if (getDialect() == Dialect.STANDARD) {
      ImmutableRefreshTokenExpectation.of(this).create();
    } else {
      ImmutableIcebergRefreshTokenExpectation.of(this).create();
    }
    ImmutableConfigEndpointExpectation.of(this).create();
    ImmutableLoadTableEndpointExpectation.of(this).create();
    createMetadataDiscoveryExpectations();
    createErrorExpectations();
  }

  public void createMetadataDiscoveryExpectations() {
    ImmutableMetadataDiscoveryExpectation.of(this).create();
  }

  public void createErrorExpectations() {
    ImmutableErrorExpectation.of(this).create();
  }
}

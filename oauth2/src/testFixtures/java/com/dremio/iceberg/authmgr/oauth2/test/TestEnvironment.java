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
import com.dremio.iceberg.authmgr.oauth2.config.ImpersonationClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ImpersonationConfig;
import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.RuntimeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProviderFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.Flow;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowContext;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowContextFactory;
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
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableImpersonationTokenExchangeExpectation;
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
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.RESTCatalog;
import org.apache.iceberg.rest.ResourcePaths;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.AuthSession;
import org.immutables.value.Value;
import org.testcontainers.shaded.org.checkerframework.checker.nullness.qual.Nullable;

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
  public boolean isImpersonationEnabled() {
    return false;
  }

  @Value.Default
  public boolean isImpersonationDiscoveryEnabled() {
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
    return new ScheduledThreadPoolExecutor(
        1,
        new ThreadFactoryBuilder()
            .setDaemon(true)
            .setNameFormat(getAgentName() + "-refresh-%d")
            .build());
  }

  @Value.Lazy
  public EndpointProvider getEndpointProvider() {
    return EndpointProviderFactory.createEndpointProvider(getAgentSpec(), getHttpClient());
  }

  @Value.Lazy
  public EndpointProvider getImpersonatinEndpointProvider() {
    return EndpointProviderFactory.createImpersonatingEndpointProvider(
        getAgentSpec(), getHttpClient());
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
  public String getImpersonationServerContextPath() {
    return "/realms/other/";
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
  public URI getImpersonationServerUrl() {
    return getServerRootUrl().resolve(getImpersonationServerContextPath());
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
  public URI getImpersonationTokenEndpoint() {
    return getImpersonationServerUrl().resolve("protocol/openid-connect/token");
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
  public URI getImpersonationDiscoveryEndpoint() {
    return getImpersonationServerUrl().resolve(getWellKnownPath());
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
        .impersonationConfig(getImpersonationConfig())
        .clientAssertionConfig(getClientAssertionConfig())
        .impersonationClientAssertionConfig(getImpersonationClientAssertionConfig())
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
            .dialect(getDialect());
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
  public Duration getImpersonationAccessTokenLifespan() {
    return getAccessTokenLifespan();
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
            .pkceTransformation(getPkceTransformation())
            .minTimeout(Duration.ofSeconds(5))
            .timeout(Duration.ofSeconds(5));
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
            .minTimeout(Duration.ofSeconds(5))
            .timeout(Duration.ofSeconds(5))
            .minPollInterval(Duration.ofMillis(100))
            .pollInterval(Duration.ofMillis(100));
    if (!isDiscoveryEnabled()) {
      builder.deviceAuthorizationEndpoint(getDeviceAuthorizationEndpoint());
    }
    return builder.build();
  }

  @Value.Default
  public TokenExchangeConfig getTokenExchangeConfig() {
    return TokenExchangeConfig.builder()
        .subjectToken(TypedToken.of(TestConstants.SUBJECT_TOKEN, TestConstants.SUBJECT_TOKEN_TYPE))
        .actorToken(TypedToken.of(TestConstants.ACTOR_TOKEN, TestConstants.ACTOR_TOKEN_TYPE))
        .requestedTokenType(TestConstants.REQUESTED_TOKEN_TYPE)
        .audience(TestConstants.AUDIENCE)
        .resource(TestConstants.RESOURCE)
        .build();
  }

  @Value.Default
  public ImpersonationConfig getImpersonationConfig() {
    ImpersonationConfig.Builder builder = ImpersonationConfig.builder();
    if (isImpersonationEnabled()) {
      builder
          .enabled(true)
          .extraRequestParameters(Map.of("impersonation", "true"))
          .clientId(getImpersonationClientId())
          .scopes(getImpersonationScopes());
      if (isPrivateClient()) {
        builder.clientSecret(getImpersonationClientSecret());
      }
      if (isImpersonationDiscoveryEnabled()) {
        builder.issuerUrl(getImpersonationServerUrl());
      } else {
        builder.tokenEndpoint(getImpersonationTokenEndpoint());
      }
      getImpersonationClientAuthentication().ifPresent(builder::clientAuthentication);
    }
    return builder.build();
  }

  @Value.Default
  public String getImpersonationClientId() {
    return TestConstants.CLIENT_ID2;
  }

  @Value.Default
  public String getImpersonationClientSecret() {
    return TestConstants.CLIENT_SECRET2;
  }

  @Value.Default
  public List<String> getImpersonationScopes() {
    return List.of(TestConstants.SCOPE2);
  }

  public abstract Optional<ClientAuthentication> getImpersonationClientAuthentication();

  @Value.Default
  public ClientAssertionConfig getClientAssertionConfig() {
    return ClientAssertionConfig.DEFAULT;
  }

  @Value.Default
  public ImpersonationClientAssertionConfig getImpersonationClientAssertionConfig() {
    return ImpersonationClientAssertionConfig.DEFAULT;
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

  @Value.Lazy
  public FlowContext getFlowContext() {
    return FlowContextFactory.createFlowContext(getAgentSpec(), getHttpClient());
  }

  @Value.Lazy
  @Nullable
  public FlowContext getImpersonationFlowContext() {
    return FlowContextFactory.createImpersonationFlowContext(getAgentSpec(), getHttpClient());
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
      switch (getGrantType()) {
        case AUTHORIZATION_CODE:
          return isUnitTest()
              ? new KeycloakAuthCodeUserEmulator(getAgentName())
              : new KeycloakAuthCodeUserEmulator(getAgentName(), USERNAME, PASSWORD);
        case DEVICE_CODE:
          return isUnitTest()
              ? new KeycloakDeviceCodeUserEmulator(getAgentName())
              : new KeycloakDeviceCodeUserEmulator(getAgentName(), USERNAME, PASSWORD);
        default:
          return UserEmulator.INACTIVE;
      }
    }
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

  public OAuth2Agent newAgent() {
    OAuth2Agent agent = new OAuth2Agent(getAgentSpec(), getExecutor(), getHttpClient());
    getUser().setErrorListener(e -> agent.close());
    return agent;
  }

  public Flow newInitialTokenFetchFlow() {
    Flow flow = FlowFactory.forInitialTokenFetch(getGrantType(), getFlowContext());
    getUser().setErrorListener(error -> flow.close());
    return flow;
  }

  public Flow newTokenRefreshFlow() {
    return FlowFactory.forTokenRefresh(getDialect(), getFlowContext());
  }

  public Flow newImpersonationFlow() {
    return FlowFactory.forImpersonation(getImpersonationFlowContext());
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
    ImmutableMetadataDiscoveryExpectation.of(this).create();
    ImmutableImpersonationTokenExchangeExpectation.of(this).create();
    if (getDialect() == Dialect.STANDARD) {
      ImmutableRefreshTokenExpectation.of(this).create();
    } else {
      ImmutableIcebergRefreshTokenExpectation.of(this).create();
    }
    ImmutableConfigEndpointExpectation.of(this).create();
    ImmutableLoadTableEndpointExpectation.of(this).create();
    createErrorExpectations();
  }

  public void createErrorExpectations() {
    ImmutableErrorExpectation.of(this).create();
  }
}

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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.System;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.HttpConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableAuthorizationCodeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableClientCredentialsExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableConfigEndpointExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableDeviceCodeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableErrorExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableLoadTableEndpointExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableMetadataDiscoveryExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutablePasswordExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableRefreshTokenExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.expectation.ImmutableTokenExchangeExpectation;
import com.dremio.iceberg.authmgr.oauth2.test.server.HttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.server.IntegrationTestHttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.server.UnitTestHttpServer;
import com.dremio.iceberg.authmgr.oauth2.test.user.InteractiveUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserBehavior;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserEmulator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import com.google.errorprone.annotations.MustBeClosed;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
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
    if (isCreateDefaultExpectations()) {
      createExpectations();
    }
  }

  @Value.Default
  public GrantType getGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public boolean isUnitTest() {
    return true;
  }

  @Value.Default
  public boolean isDiscoveryEnabled() {
    return true;
  }

  @Value.Default
  public boolean isReturnRefreshTokens() {
    return !getGrantType().equals(GrantType.CLIENT_CREDENTIALS);
  }

  @Value.Default
  public boolean isReturnRefreshTokenLifespan() {
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
    return isUnitTest() ? new UnitTestHttpServer(isSsl()) : new IntegrationTestHttpServer();
  }

  @Value.Default
  public boolean isSsl() {
    return false;
  }

  @Value.Default
  public ScheduledExecutorService getExecutor() {
    return ThreadPools.newScheduledPool(getAgentName() + "-refresh", getExecutorPoolSize());
  }

  @Value.Default
  public int getExecutorPoolSize() {
    return 1;
  }

  public void reset() {
    getServer().reset();
  }

  @Override
  public void close() {
    getUser().close();
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
    return ".well-known/openid-configuration";
  }

  @Value.Default
  public URI getDiscoveryEndpoint() {
    return getAuthorizationServerUrl().resolve(getWellKnownPath());
  }

  @Value.Default
  public OAuth2Config getOAuth2Config() {
    return OAuth2Config.builder()
        .basicConfig(getBasicConfig())
        .resourceOwnerConfig(getResourceOwnerConfig())
        .authorizationCodeConfig(getAuthorizationCodeConfig())
        .deviceCodeConfig(getDeviceCodeConfig())
        .tokenRefreshConfig(getTokenRefreshConfig())
        .tokenExchangeConfig(getTokenExchangeConfig())
        .clientAssertionConfig(getClientAssertionConfig())
        .systemConfig(getSystemConfig())
        .httpConfig(getHttpConfig())
        .build();
  }

  @Value.Default
  public BasicConfig getBasicConfig() {
    BasicConfig.Builder builder =
        BasicConfig.builder()
            .grantType(getGrantType())
            .clientAuthenticationMethod(getClientAuthenticationMethod())
            .scope(getScope())
            .extraRequestParameters(getExtraRequestParameters())
            .minTimeout(getTimeout())
            .timeout(getTimeout());
    if (getToken().isPresent()) {
      builder.token(getToken().get());
    } else {
      builder.clientId(getClientId());
    }
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.clientSecret(getClientSecret());
    }
    if (isDiscoveryEnabled()) {
      builder.issuerUrl(getAuthorizationServerUrl());
    } else {
      builder.tokenEndpoint(getTokenEndpoint());
    }
    return builder.build();
  }

  @Value.Default
  public ClientID getClientId() {
    return TestConstants.CLIENT_ID1;
  }

  @Value.Default
  public Secret getClientSecret() {
    return TestConstants.CLIENT_SECRET1;
  }

  @Value.Default
  public ClientAuthenticationMethod getClientAuthenticationMethod() {
    return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
  }

  public abstract Optional<AccessToken> getToken();

  @Value.Default
  public Scope getScope() {
    return TestConstants.SCOPE1;
  }

  @Value.Default
  public Map<String, String> getExtraRequestParameters() {
    return Map.of("extra1", "value1");
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
    return ResourceOwnerConfig.builder().username(getUsername()).password(getPassword()).build();
  }

  @Value.Default
  public String getUsername() {
    return TestConstants.USERNAME;
  }

  @Value.Default
  public Secret getPassword() {
    return TestConstants.PASSWORD;
  }

  @Value.Default
  public AuthorizationCodeConfig getAuthorizationCodeConfig() {
    AuthorizationCodeConfig.Builder builder =
        AuthorizationCodeConfig.builder()
            .pkceEnabled(isPkceEnabled())
            .codeChallengeMethod(getCodeChallengeMethod());
    if (!isDiscoveryEnabled()) {
      builder.authorizationEndpoint(getAuthorizationEndpoint());
    }
    getRedirectUri().ifPresent(builder::redirectUri);
    return builder.build();
  }

  @Value.Default
  public boolean isPkceEnabled() {
    return true;
  }

  @Value.Default
  public CodeChallengeMethod getCodeChallengeMethod() {
    return CodeChallengeMethod.S256;
  }

  public abstract Optional<URI> getRedirectUri();

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
      builder.audiences(List.of(getAudience()));
    }
    if (getResource() != null) {
      builder.resources(List.of(getResource()));
    }
    return builder.build();
  }

  @Value.Default
  @Nullable
  public Token getSubjectToken() {
    return TestConstants.SUBJECT_TOKEN;
  }

  @Value.Default
  public TokenTypeURI getSubjectTokenType() {
    return TestConstants.SUBJECT_TOKEN_TYPE;
  }

  @Value.Default
  public GrantType getSubjectGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public ClientID getSubjectClientId() {
    return TestConstants.CLIENT_ID2;
  }

  @Value.Default
  public Secret getSubjectClientSecret() {
    return TestConstants.CLIENT_SECRET2;
  }

  @Value.Default
  public Scope getSubjectScope() {
    return TestConstants.SCOPE2;
  }

  @Value.Default
  public Map<String, String> getSubjectTokenConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(Basic.GRANT_TYPE, getSubjectGrantType().getValue())
            .put(Basic.CLIENT_ID, getSubjectClientId().getValue())
            .put(Basic.EXTRA_PARAMS_PREFIX + "extra2", "value2")
            .put(Basic.SCOPE, getSubjectScope().toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(Basic.CLIENT_SECRET, getSubjectClientSecret().getValue());
    }
    return builder.build();
  }

  @Value.Default
  @Nullable
  public Token getActorToken() {
    return TestConstants.ACTOR_TOKEN;
  }

  @Value.Default
  public TokenTypeURI getActorTokenType() {
    return TestConstants.ACTOR_TOKEN_TYPE;
  }

  @Value.Default
  public GrantType getActorGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public ClientID getActorClientId() {
    return TestConstants.CLIENT_ID1;
  }

  @Value.Default
  public Secret getActorClientSecret() {
    return TestConstants.CLIENT_SECRET1;
  }

  @Value.Default
  public Scope getActorScope() {
    return TestConstants.SCOPE1;
  }

  @Value.Default
  public Map<String, String> getActorTokenConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(Basic.GRANT_TYPE, getActorGrantType().getValue())
            .put(Basic.CLIENT_ID, getActorClientId().getValue())
            .put(Basic.EXTRA_PARAMS_PREFIX + "extra2", "value2")
            .put(Basic.SCOPE, getActorScope().toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(Basic.CLIENT_SECRET, getActorClientSecret().getValue());
    }
    return builder.build();
  }

  @Value.Default
  public TokenTypeURI getRequestedTokenType() {
    return TestConstants.REQUESTED_TOKEN_TYPE;
  }

  @Value.Default
  @Nullable
  public Audience getAudience() {
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
  public SystemConfig getSystemConfig() {
    return SystemConfig.builder()
        .agentName(getAgentName())
        .clock(getClock())
        .console(getConsole())
        .build();
  }

  @Value.Default
  public Clock getClock() {
    return new TestClock(TestConstants.NOW);
  }

  @Value.Default
  public String getAgentName() {
    return "iceberg-auth-manager-" + java.lang.System.nanoTime();
  }

  @Value.Derived
  public PrintStream getConsole() {
    return getUser().getConsole();
  }

  @Value.Default
  public HttpConfig getHttpConfig() {
    HttpConfig.Builder builder =
        HttpConfig.builder()
            .clientType(getHttpClientType())
            .sslProtocols(getSslProtocols())
            .sslCipherSuites(getSslCipherSuites())
            .sslTrustAll(isSslTrustAll())
            .compressionEnabled(isCompressionEnabled());
    getProxyHost().ifPresent(builder::proxyHost);
    getProxyPort().ifPresent(builder::proxyPort);
    getProxyUsername().ifPresent(builder::proxyUsername);
    getProxyPassword().ifPresent(builder::proxyPassword);
    getSslTrustStorePath().ifPresent(builder::sslTrustStorePath);
    getSslTrustStorePassword().ifPresent(builder::sslTrustStorePassword);
    return builder.build();
  }

  @Value.Default
  public HttpClientType getHttpClientType() {
    return HttpClientType.DEFAULT;
  }

  public abstract List<String> getSslProtocols();

  public abstract List<String> getSslCipherSuites();

  @Value.Default
  public boolean isSslTrustAll() {
    return false;
  }

  @Value.Default
  public boolean isCompressionEnabled() {
    return true;
  }

  public abstract Optional<String> getProxyHost();

  public abstract OptionalInt getProxyPort();

  public abstract Optional<String> getProxyUsername();

  public abstract Optional<String> getProxyPassword();

  public abstract Optional<Path> getSslTrustStorePath();

  public abstract Optional<String> getSslTrustStorePassword();

  @Value.Default
  public boolean isForceInactiveUser() {
    return false;
  }

  @Value.Default
  public UserBehavior getUserBehavior() {
    return isUnitTest() ? UserBehavior.UNIT_TESTS : UserBehavior.INTEGRATION_TESTS;
  }

  @Value.Default
  public UserEmulator getUser() {
    if (isForceInactiveUser()) {
      return UserEmulator.INACTIVE;
    } else {
      GrantType mainGrant = getGrantType();
      GrantType subjectGrant = getSubjectGrantType();
      GrantType actorGrant = getActorGrantType();
      if (ConfigUtils.requiresUserInteraction(mainGrant)
          || ConfigUtils.requiresUserInteraction(subjectGrant)
          || ConfigUtils.requiresUserInteraction(actorGrant)) {
        return new InteractiveUserEmulator(getUserBehavior());
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
        .put(Basic.CLIENT_ID, getClientId().getValue())
        .put(Basic.CLIENT_SECRET, getClientSecret().getValue())
        .put(Basic.SCOPE, getScope().toString())
        .put(Basic.EXTRA_PARAMS_PREFIX + "extra1", "value1")
        .put(System.AGENT_NAME, getAgentName())
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

  public HTTPClient.Builder newIcebergRestClientBuilder(Map<String, String> properties) {
    return HTTPClient.builder(properties)
        .uri(getCatalogServerUrl())
        .withAuthSession(AuthSession.EMPTY);
  }

  @MustBeClosed
  public RESTCatalog newCatalog() {
    RESTCatalog catalog =
        new RESTCatalog(getSessionContext(), config -> newIcebergRestClientBuilder(config).build());
    UserEmulator user = getUser();
    user.addErrorListener(
        e -> {
          try {
            catalog.close();
          } catch (IOException ex) {
            throw new RuntimeException(ex);
          }
        });
    catalog.initialize("catalog-" + java.lang.System.nanoTime(), getCatalogProperties());
    return catalog;
  }

  @MustBeClosed
  public FlowFactory newFlowFactory() {
    return FlowFactory.create(getOAuth2Config(), getExecutor());
  }

  @MustBeClosed
  public OAuth2Agent newAgent() {
    OAuth2Agent agent = new OAuth2Agent(getOAuth2Config(), getExecutor());
    getUser().addErrorListener(e -> agent.close());
    return agent;
  }

  public void createExpectations() {
    createInitialGrantExpectations(getGrantType());
    createRefreshTokenExpectations();
    createCatalogExpectations();
    createMetadataDiscoveryExpectations();
    createErrorExpectations();
  }

  public void createInitialGrantExpectations(GrantType grantType) {
    if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {
      ImmutableClientCredentialsExpectation.of(this).create();
    } else if (grantType.equals(GrantType.PASSWORD)) {
      ImmutablePasswordExpectation.of(this).create();
    } else if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {
      ImmutableAuthorizationCodeExpectation.of(this).create();
    } else if (grantType.equals(GrantType.DEVICE_CODE)) {
      ImmutableDeviceCodeExpectation.of(this).create();
    } else if (grantType.equals(GrantType.TOKEN_EXCHANGE)) {
      ImmutableTokenExchangeExpectation.of(this).create();
      createInitialGrantExpectations(getSubjectGrantType());
      createInitialGrantExpectations(getActorGrantType());
    }
  }

  public void createRefreshTokenExpectations() {
    if (isTokenRefreshEnabled()) {
      ImmutableRefreshTokenExpectation.of(this).create();
    }
  }

  public void createCatalogExpectations() {
    ImmutableConfigEndpointExpectation.of(this).create();
    ImmutableLoadTableEndpointExpectation.of(this).create();
  }

  public void createMetadataDiscoveryExpectations() {
    ImmutableMetadataDiscoveryExpectation.of(this).create();
  }

  public void createErrorExpectations() {
    ImmutableErrorExpectation.of(this).create();
  }

  // Prevent generation of equals(), hashCode() and toString() as this class is big
  // and the generated methods are not useful.

  @Override
  public final int hashCode() {
    return java.lang.System.identityHashCode(this);
  }

  @Override
  public final boolean equals(Object obj) {
    return this == obj;
  }

  @Override
  public final String toString() {
    return "TestEnvironment";
  }
}

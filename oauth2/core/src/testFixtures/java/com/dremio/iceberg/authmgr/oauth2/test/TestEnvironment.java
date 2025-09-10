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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.agent.ImmutableOAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
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
    Map<String, String> properties =
        ImmutableMap.<String, String>builder()
            .putAll(getBasicConfig())
            .putAll(getResourceOwnerConfig())
            .putAll(getAuthorizationCodeConfig())
            .putAll(getDeviceCodeConfig())
            .putAll(getTokenRefreshConfig())
            .putAll(getTokenExchangeConfig())
            .putAll(getClientAssertionConfig())
            .putAll(getSystemConfig())
            .putAll(getHttpConfig())
            .build();
    return OAuth2Config.from(properties);
  }

  @Value.Default
  public Map<String, String> getBasicConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(PREFIX + '.' + BasicConfig.GRANT_TYPE, getGrantType().getValue())
            .put(PREFIX + '.' + BasicConfig.CLIENT_AUTH, getClientAuthenticationMethod().toString())
            .put(PREFIX + '.' + BasicConfig.SCOPE, getScope().toString())
            .putAll(
                ConfigUtils.prefixedMap(
                    getExtraRequestParameters(), PREFIX + '.' + BasicConfig.EXTRA_PARAMS))
            .put(PREFIX + '.' + BasicConfig.TIMEOUT, getTimeout().toString())
            .put(PREFIX + '.' + "min-timeout", getTimeout().toString());
    if (getToken().isPresent()) {
      builder.put(PREFIX + '.' + BasicConfig.TOKEN, getToken().get().getValue());
    } else {
      builder.put(PREFIX + '.' + BasicConfig.CLIENT_ID, getClientId().getValue());
    }
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, getClientSecret().getValue());
    }
    if (isDiscoveryEnabled()) {
      builder.put(PREFIX + '.' + BasicConfig.ISSUER_URL, getAuthorizationServerUrl().toString());
    } else {
      builder.put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, getTokenEndpoint().toString());
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

  public abstract Optional<TypelessAccessToken> getToken();

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
    return isUnitTest() ? Duration.ofSeconds(5) : Duration.parse(BasicConfig.DEFAULT_TIMEOUT);
  }

  @Value.Default
  public Map<String, String> getTokenRefreshConfig() {
    return ImmutableMap.<String, String>builder()
        .put(
            TokenRefreshConfig.PREFIX + '.' + TokenRefreshConfig.ENABLED,
            String.valueOf(isTokenRefreshEnabled()))
        .put(
            TokenRefreshConfig.PREFIX + '.' + TokenRefreshConfig.ACCESS_TOKEN_LIFESPAN,
            getAccessTokenLifespan().toString())
        .put(TokenRefreshConfig.PREFIX + '.' + TokenRefreshConfig.SAFETY_WINDOW, "PT5S")
        .put(TokenRefreshConfig.PREFIX + '.' + TokenRefreshConfig.IDLE_TIMEOUT, "PT5S")
        .put(TokenRefreshConfig.PREFIX + '.' + "min-refresh-delay", "PT5S")
        .put(TokenRefreshConfig.PREFIX + '.' + "min-idle-timeout", "PT5S")
        .put(TokenRefreshConfig.PREFIX + '.' + "min-access-token-lifespan", "PT5S")
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
  public Map<String, String> getResourceOwnerConfig() {
    return ImmutableMap.<String, String>builder()
        .put(ResourceOwnerConfig.PREFIX + '.' + ResourceOwnerConfig.USERNAME, getUsername())
        .put(
            ResourceOwnerConfig.PREFIX + '.' + ResourceOwnerConfig.PASSWORD,
            getPassword().getValue())
        .build();
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
  public Map<String, String> getAuthorizationCodeConfig() {
    String prefix = AuthorizationCodeConfig.PREFIX;
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(
                prefix + '.' + AuthorizationCodeConfig.PKCE_ENABLED,
                String.valueOf(isPkceEnabled()))
            .put(
                prefix + '.' + AuthorizationCodeConfig.PKCE_METHOD,
                getCodeChallengeMethod().toString())
            .put(
                prefix + '.' + AuthorizationCodeConfig.CALLBACK_HTTPS,
                String.valueOf(isCallbackHttps()));
    if (!isDiscoveryEnabled()) {
      builder.put(
          prefix + '.' + AuthorizationCodeConfig.ENDPOINT, getAuthorizationEndpoint().toString());
    }
    getRedirectUri()
        .ifPresent(
            u -> builder.put(prefix + '.' + AuthorizationCodeConfig.REDIRECT_URI, u.toString()));
    if (isCallbackHttps()) {
      getSslKeyStorePath()
          .ifPresent(
              p ->
                  builder.put(
                      prefix + '.' + AuthorizationCodeConfig.SSL_KEYSTORE_PATH, p.toString()));
      getSslKeyStorePassword()
          .ifPresent(
              p -> builder.put(prefix + '.' + AuthorizationCodeConfig.SSL_KEYSTORE_PASSWORD, p));
      getSslKeyStoreAlias()
          .ifPresent(
              a -> builder.put(prefix + '.' + AuthorizationCodeConfig.SSL_KEYSTORE_ALIAS, a));
    }
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
  public boolean isCallbackHttps() {
    return false;
  }

  public abstract Optional<Path> getSslKeyStorePath();

  public abstract Optional<String> getSslKeyStorePassword();

  public abstract Optional<String> getSslKeyStoreAlias();

  @Value.Default
  public Map<String, String> getDeviceCodeConfig() {
    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
    builder
        .put(DeviceCodeConfig.PREFIX + '.' + DeviceCodeConfig.POLL_INTERVAL, "PT0.01S")
        .put(DeviceCodeConfig.PREFIX + '.' + "min-poll-interval", "PT0.01S")
        .put(
            DeviceCodeConfig.PREFIX + '.' + "ignore-server-poll-interval",
            isUnitTest() ? "true" : "false");
    if (!isDiscoveryEnabled()) {
      builder.put(
          DeviceCodeConfig.PREFIX + '.' + DeviceCodeConfig.ENDPOINT,
          getDeviceAuthorizationEndpoint().toString());
    }
    return builder.build();
  }

  @Value.Default
  public Map<String, String> getTokenExchangeConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN_TYPE,
                getSubjectTokenType().toString())
            .put(
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN_TYPE,
                getActorTokenType().toString())
            .put(
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.REQUESTED_TOKEN_TYPE,
                getRequestedTokenType().toString());
    getSubjectTokenConfig()
        .forEach(
            (k, v) ->
                builder.put(
                    TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN + '.' + k,
                    v));
    getActorTokenConfig()
        .forEach(
            (k, v) ->
                builder.put(
                    TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN + '.' + k,
                    v));
    if (getSubjectToken() != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN,
          getSubjectToken().getValue());
    }
    if (getActorToken() != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN,
          getActorToken().getValue());
    }
    if (getAudience() != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.AUDIENCE,
          getAudience().toString());
    }
    if (getResource() != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.RESOURCE,
          getResource().toString());
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
            .put(BasicConfig.GRANT_TYPE, getSubjectGrantType().getValue())
            .put(BasicConfig.CLIENT_ID, getSubjectClientId().getValue())
            .put(BasicConfig.EXTRA_PARAMS + ".extra2", "value2")
            .put(BasicConfig.SCOPE, getSubjectScope().toString())
            .put(
                DeviceCodeConfig.GROUP_NAME + "." + DeviceCodeConfig.POLL_INTERVAL,
                Duration.ofMillis(10).toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(BasicConfig.CLIENT_SECRET, getSubjectClientSecret().getValue());
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
            .put(BasicConfig.GRANT_TYPE, getActorGrantType().getValue())
            .put(BasicConfig.CLIENT_ID, getActorClientId().getValue())
            .put(BasicConfig.EXTRA_PARAMS + ".extra2", "value2")
            .put(BasicConfig.SCOPE, getActorScope().toString())
            .put(
                DeviceCodeConfig.GROUP_NAME + "." + DeviceCodeConfig.POLL_INTERVAL,
                Duration.ofMillis(10).toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(BasicConfig.CLIENT_SECRET, getActorClientSecret().getValue());
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
  public Map<String, String> getClientAssertionConfig() {
    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
    getJwsAlgorithm()
        .ifPresent(
            v ->
                builder.put(
                    ClientAssertionConfig.PREFIX + '.' + ClientAssertionConfig.ALGORITHM,
                    v.getName()));
    getPrivateKey()
        .ifPresent(
            v ->
                builder.put(
                    ClientAssertionConfig.PREFIX + '.' + ClientAssertionConfig.PRIVATE_KEY,
                    v.toString()));
    return builder.build();
  }

  public abstract Optional<JWSAlgorithm> getJwsAlgorithm();

  public abstract Optional<Path> getPrivateKey();

  @Value.Default
  public Map<String, String> getSystemConfig() {
    return ImmutableMap.<String, String>builder()
        .put(SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getAgentName())
        .put(SystemConfig.PREFIX + '.' + SystemConfig.SESSION_CACHE_TIMEOUT, "PT1H")
        .build();
  }

  @Value.Default
  public String getAgentName() {
    return "iceberg-auth-manager-" + java.lang.System.nanoTime();
  }

  @Value.Default
  public Map<String, String> getHttpConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(HttpConfig.PREFIX + '.' + HttpConfig.CLIENT_TYPE, getHttpClientType().toString())
            .put(
                HttpConfig.PREFIX + '.' + HttpConfig.SSL_TRUST_ALL,
                String.valueOf(isSslTrustAll()));
    getSslProtocols()
        .ifPresent(v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.SSL_PROTOCOLS, v));
    getSslCipherSuites()
        .ifPresent(v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.SSL_CIPHER_SUITES, v));
    getProxyHost().ifPresent(v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.PROXY_HOST, v));
    getProxyPort()
        .ifPresent(
            v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.PROXY_PORT, String.valueOf(v)));
    getProxyUsername()
        .ifPresent(v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.PROXY_USERNAME, v));
    getProxyPassword()
        .ifPresent(v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.PROXY_PASSWORD, v));
    getSslTrustStorePath()
        .ifPresent(
            v ->
                builder.put(
                    HttpConfig.PREFIX + '.' + HttpConfig.SSL_TRUSTSTORE_PATH, v.toString()));
    getSslTrustStorePassword()
        .ifPresent(
            v -> builder.put(HttpConfig.PREFIX + '.' + HttpConfig.SSL_TRUSTSTORE_PASSWORD, v));
    return builder.build();
  }

  @Value.Default
  public HttpClientType getHttpClientType() {
    return HttpClientType.DEFAULT;
  }

  public abstract Optional<String> getSslProtocols();

  public abstract Optional<String> getSslCipherSuites();

  @Value.Default
  public boolean isSslTrustAll() {
    return false;
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
        return new InteractiveUserEmulator(getUserBehavior(), getUserSslContext());
      }
    }
    return UserEmulator.INACTIVE;
  }

  @Value.Default
  public SSLContext getUserSslContext() {
    try {
      return SSLContext.getDefault();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Value.Default
  public Map<String, String> getCatalogProperties() {
    return ImmutableMap.<String, String>builder()
        .put(CatalogProperties.URI, getCatalogServerUrl().toString())
        .put("prefix", TestConstants.WAREHOUSE)
        .put(CatalogProperties.FILE_IO_IMPL, "org.apache.iceberg.inmemory.InMemoryFileIO")
        .put(AuthProperties.AUTH_TYPE, OAuth2Manager.class.getName())
        .put(PREFIX + '.' + BasicConfig.GRANT_TYPE, getGrantType().toString())
        .put(PREFIX + '.' + BasicConfig.ISSUER_URL, getAuthorizationServerUrl().toString())
        .put(PREFIX + '.' + BasicConfig.CLIENT_ID, getClientId().getValue())
        .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, getClientSecret().getValue())
        .put(PREFIX + '.' + BasicConfig.SCOPE, getScope().toString())
        .put(PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1", "value1")
        .put(SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getAgentName())
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

  @Value.Default
  public OAuth2AgentRuntime getOAuth2AgentRuntime() {
    return ImmutableOAuth2AgentRuntime.builder()
        .executor(getExecutor())
        .clock(getClock())
        .console(getConsole())
        .build();
  }

  @Value.Default
  public Clock getClock() {
    return isUnitTest() ? new TestClock(TestConstants.NOW) : Clock.systemUTC();
  }

  @Value.Derived
  public PrintStream getConsole() {
    return getUser().getConsole();
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
    return FlowFactory.create(getOAuth2Config(), getOAuth2AgentRuntime());
  }

  @MustBeClosed
  public OAuth2Agent newAgent() {
    OAuth2Agent agent = new OAuth2Agent(getOAuth2Config(), getOAuth2AgentRuntime());
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

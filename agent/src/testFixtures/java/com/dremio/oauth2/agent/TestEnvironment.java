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
package com.dremio.oauth2.agent;

import static com.dremio.oauth2.agent.OAuth2AgentConfig.PREFIX;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.dremio.oauth2.agent.config.AuthorizationCodeConfig;
import com.dremio.oauth2.agent.config.BasicConfig;
import com.dremio.oauth2.agent.config.ConfigUtils;
import com.dremio.oauth2.agent.config.DeviceCodeConfig;
import com.dremio.oauth2.agent.config.DpopConfig;
import com.dremio.oauth2.agent.config.HttpConfig;
import com.dremio.oauth2.agent.config.JwtBearerConfig;
import com.dremio.oauth2.agent.config.JwtClientAuthConfig;
import com.dremio.oauth2.agent.config.ResourceOwnerConfig;
import com.dremio.oauth2.agent.config.SystemConfig;
import com.dremio.oauth2.agent.config.TokenExchangeConfig;
import com.dremio.oauth2.agent.config.TokenRefreshConfig;
import com.dremio.oauth2.agent.expectation.ImmutableAuthorizationCodeExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableClientCredentialsExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableDeviceCodeExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableErrorExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableJwtBearerExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableMetadataDiscoveryExpectation;
import com.dremio.oauth2.agent.expectation.ImmutablePasswordExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableRefreshTokenExpectation;
import com.dremio.oauth2.agent.expectation.ImmutableTokenExchangeExpectation;
import com.dremio.oauth2.agent.flow.FlowFactory;
import com.dremio.oauth2.agent.http.HttpClientType;
import com.dremio.oauth2.agent.user.InteractiveUserEmulator;
import com.dremio.oauth2.agent.user.UserBehavior;
import com.dremio.oauth2.agent.user.UserEmulator;
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
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.immutables.value.Value;

@AuthManagerImmutable
@Value.Immutable(copy = false)
public abstract class TestEnvironment implements AutoCloseable {

  private static final AtomicInteger ID_COUNTER = new AtomicInteger();

  @Value.Check
  public void validate() {
    if (isCreateDefaultExpectations()) {
      createExpectations();
    }
  }

  @Value.Default
  public String getId() {
    return "env" + ID_COUNTER.incrementAndGet();
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

  @Value.Default
  public boolean isSsl() {
    return false;
  }

  @Value.Default
  public ScheduledExecutorService getExecutor() {
    return Executors.newScheduledThreadPool(getExecutorPoolSize());
  }

  @Value.Default
  public int getExecutorPoolSize() {
    return 1;
  }

  public void reset() {
    if (isUnitTest()) {
      TestServer.clear(getId());
    }
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
    reset();
  }

  @Value.Default
  public URI getServerRootUrl() {
    if (!isUnitTest()) {
      throw new IllegalStateException("Server root URL must be provided for integration tests");
    }
    return URI.create(
        (isSsl() ? "https" : "http")
            + "://localhost:"
            + TestServer.getInstance().getLocalPort()
            + "/"
            + getId()
            + "/");
  }

  @Value.Default
  public String getAuthorizationServerContextPath() {
    return "realms/master/";
  }

  @Value.Default
  public String getCatalogServerContextPath() {
    return "api/catalog/";
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
    return getCatalogServerUrl().resolve("v1/config");
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
  public Map<String, String> getProperties() {
    return ImmutableMap.<String, String>builder()
        .putAll(getBasicConfig())
        .putAll(getResourceOwnerConfig())
        .putAll(getAuthorizationCodeConfig())
        .putAll(getDeviceCodeConfig())
        .putAll(getTokenRefreshConfig())
        .putAll(getTokenExchangeConfig())
        .putAll(getJwtBearerGrantConfig())
        .putAll(getJwtClientAuthConfig())
        .putAll(getDpopConfig())
        .putAll(getSystemConfig())
        .putAll(getHttpConfig())
        .build();
  }

  @Value.Default
  public OAuth2AgentConfig getOAuth2Config() {
    return OAuth2AgentConfig.from(getProperties());
  }

  @Value.Default
  public Map<String, String> getDpopConfig() {
    return Map.of(
        DpopConfig.PREFIX + '.' + DpopConfig.ENABLED, String.valueOf(isDpopEnabled()),
        DpopConfig.PREFIX + '.' + DpopConfig.ALGORITHM, getDpopAlgorithm().getName());
  }

  @Value.Default
  public boolean isDpopEnabled() {
    return false;
  }

  @Value.Default
  public JWSAlgorithm getDpopAlgorithm() {
    return JWSAlgorithm.ES256;
  }

  @Value.Default
  public String getDpopNonce() {
    return "test-dpop-nonce";
  }

  @Value.Default
  public boolean isRequireDpopNonce() {
    return false;
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
    if (!isDiscoveryEnabled()) {
      builder.put(
          DeviceCodeConfig.PREFIX + '.' + DeviceCodeConfig.ENDPOINT,
          getDeviceAuthorizationEndpoint().toString());
    }
    return builder.build();
  }

  @Value.Default
  public Map<String, String> getJwtBearerGrantConfig() {
    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
    getAssertionConfig()
        .forEach(
            (k, v) ->
                builder.put(JwtBearerConfig.PREFIX + '.' + JwtBearerConfig.ASSERTION + '.' + k, v));
    if (getAssertion() != null) {
      builder.put(JwtBearerConfig.PREFIX + '.' + JwtBearerConfig.ASSERTION, getAssertion());
    }
    return builder.build();
  }

  @Value.Default
  @Nullable
  public String getAssertion() {
    return TestConstants.ASSERTION_TOKEN;
  }

  @Value.Default
  public GrantType getAssertionGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  @Value.Default
  public ClientID getAssertionClientId() {
    return TestConstants.CLIENT_ID2;
  }

  @Value.Default
  public Secret getAssertionClientSecret() {
    return TestConstants.CLIENT_SECRET2;
  }

  @Value.Default
  public Scope getAssertionScope() {
    return TestConstants.SCOPE2;
  }

  @Value.Default
  public Map<String, String> getAssertionConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .putAll(stripPrefix(getBasicConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getResourceOwnerConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getAuthorizationCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getDeviceCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getTokenRefreshConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getJwtClientAuthConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getSystemConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getHttpConfig(), PREFIX + '.'))
            .put(BasicConfig.GRANT_TYPE, getAssertionGrantType().getValue())
            .put(BasicConfig.CLIENT_ID, getAssertionClientId().getValue())
            .put(BasicConfig.EXTRA_PARAMS + ".extra2", "value2")
            .put(BasicConfig.SCOPE, getAssertionScope().toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(BasicConfig.CLIENT_SECRET, getAssertionClientSecret().getValue());
    }
    return builder.buildKeepingLast();
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
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.AUDIENCES,
          getAudience().toString());
    }
    if (getResource() != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.RESOURCES,
          getResource().toString());
    }
    return builder.build();
  }

  @Value.Default
  @Nullable
  public Token getSubjectToken() {
    return new TypelessAccessToken(TestConstants.SUBJECT_TOKEN);
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
            .putAll(stripPrefix(getBasicConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getResourceOwnerConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getAuthorizationCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getDeviceCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getTokenRefreshConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getJwtClientAuthConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getSystemConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getHttpConfig(), PREFIX + '.'))
            .put(BasicConfig.GRANT_TYPE, getSubjectGrantType().getValue())
            .put(BasicConfig.CLIENT_ID, getSubjectClientId().getValue())
            .put(BasicConfig.EXTRA_PARAMS + ".extra2", "value2")
            .put(BasicConfig.SCOPE, getSubjectScope().toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(BasicConfig.CLIENT_SECRET, getSubjectClientSecret().getValue());
    }
    return builder.buildKeepingLast();
  }

  @Value.Default
  @Nullable
  public Token getActorToken() {
    return new TypelessAccessToken(TestConstants.ACTOR_TOKEN);
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
            .putAll(stripPrefix(getBasicConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getResourceOwnerConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getAuthorizationCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getDeviceCodeConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getTokenRefreshConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getJwtClientAuthConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getSystemConfig(), PREFIX + '.'))
            .putAll(stripPrefix(getHttpConfig(), PREFIX + '.'))
            .put(BasicConfig.GRANT_TYPE, getActorGrantType().getValue())
            .put(BasicConfig.CLIENT_ID, getActorClientId().getValue())
            .put(BasicConfig.EXTRA_PARAMS + ".extra2", "value2")
            .put(BasicConfig.SCOPE, getActorScope().toString());
    if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
      builder.put(BasicConfig.CLIENT_SECRET, getActorClientSecret().getValue());
    }
    return builder.buildKeepingLast();
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
  public Map<String, String> getJwtClientAuthConfig() {
    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
    getJwtClientAuthAlgorithm()
        .ifPresent(
            v ->
                builder.put(
                    JwtClientAuthConfig.PREFIX + '.' + JwtClientAuthConfig.ALGORITHM, v.getName()));
    getJwtClientAuthPrivateKey()
        .ifPresent(
            v ->
                builder.put(
                    JwtClientAuthConfig.PREFIX + '.' + JwtClientAuthConfig.PRIVATE_KEY,
                    v.toString()));
    return builder.build();
  }

  public abstract Optional<JWSAlgorithm> getJwtClientAuthAlgorithm();

  public abstract Optional<Path> getJwtClientAuthPrivateKey();

  @Value.Default
  public Map<String, String> getSystemConfig() {
    return ImmutableMap.<String, String>builder()
        .put(SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getAgentName())
        .put(SystemConfig.PREFIX + '.' + SystemConfig.SESSION_CACHE_TIMEOUT, "PT1H")
        .build();
  }

  @Value.Default
  public String getAgentName() {
    return "iceberg-auth-manager-" + System.nanoTime();
  }

  @Value.Default
  public Map<String, String> getHttpConfig() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder()
            .put(HttpConfig.PREFIX + '.' + HttpConfig.CLIENT_TYPE, getHttpClientType().toString())
            .put(
                HttpConfig.PREFIX + '.' + HttpConfig.SSL_TRUST_ALL, String.valueOf(isSslTrustAll()))
            .put(
                HttpConfig.PREFIX + '.' + HttpConfig.SSL_HOSTNAME_VERIFICATION_ENABLED,
                String.valueOf(isSslHostnameVerificationEnabled()));
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

  @Value.Default
  public boolean isSslHostnameVerificationEnabled() {
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
      if (ConfigUtils.requiresUserInteraction(getGrantType())
          || (getSubjectToken() == null
              && ConfigUtils.requiresUserInteraction(getSubjectGrantType()))
          || (getActorToken() == null //
              && ConfigUtils.requiresUserInteraction(getActorGrantType()))
          || (getAssertion() == null
              && ConfigUtils.requiresUserInteraction(getAssertionGrantType()))) {
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
    createMetadataDiscoveryExpectations();
    createOtherExpectations();
    createErrorExpectations();
  }

  public void createOtherExpectations() {}

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
      if (getSubjectToken() == null) {
        createInitialGrantExpectations(getSubjectGrantType());
      }
      if (getActorToken() == null) {
        createInitialGrantExpectations(getActorGrantType());
      }
    } else if (grantType.equals(GrantType.JWT_BEARER)) {
      ImmutableJwtBearerExpectation.of(this).create();
      if (getAssertion() == null) {
        createInitialGrantExpectations(getAssertionGrantType());
      }
    }
  }

  public void createRefreshTokenExpectations() {
    if (isTokenRefreshEnabled()) {
      ImmutableRefreshTokenExpectation.of(this).create();
    }
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
    return System.identityHashCode(this);
  }

  @Override
  public final boolean equals(Object obj) {
    return this == obj;
  }

  @Override
  public final String toString() {
    return "TestEnvironment";
  }

  static Map<String, String> stripPrefix(Map<String, String> map, String prefix) {
    return map.entrySet().stream()
        .filter(e -> e.getKey().startsWith(prefix))
        .collect(Collectors.toMap(e -> e.getKey().substring(prefix.length()), Map.Entry::getValue));
  }
}

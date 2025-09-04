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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertAccessToken;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokensResult;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.InstanceOfAssertFactories.ATOMIC_BOOLEAN;
import static org.assertj.core.api.InstanceOfAssertFactories.throwable;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.verify.VerificationTimes.atLeast;

import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.CryptoUtils;
import com.dremio.iceberg.authmgr.oauth2.test.TestClock;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserBehavior;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.provider.EnumSource;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Enum;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpForward;

@ExtendWith(SoftAssertionsExtension.class)
class OAuth2AgentTest {

  @InjectSoftAssertions protected SoftAssertions soft;

  @CartesianTest
  void testClientCredentials(
      @Enum HttpClientType httpClientType,
      @EnumLike(excludes = "none") ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @Test
  void testClientCredentialsUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder().clientId(new ClientID("WrongClient")).build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(throwable(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .satisfies(
              r -> {
                soft.assertThat(r.getCode()).isEqualTo("invalid_request");
                soft.assertThat(r.getDescription()).contains("Invalid request");
              });
    }
  }

  @CartesianTest
  void testPassword(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @Test
  void testPasswordUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .password(new Secret("WrongPassword"))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(throwable(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .satisfies(
              r -> {
                soft.assertThat(r.getCode()).isEqualTo("invalid_request");
                soft.assertThat(r.getDescription()).contains("Invalid request");
              });
    }
  }

  @CartesianTest
  void testAuthorizationCode(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @Test
  void testAuthorizationCodeTimeout() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .timeout(Duration.ofMillis(10))
                .forceInactiveUser(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .hasMessage("Timed out waiting for an access token")
          .cause()
          .isInstanceOf(TimeoutException.class);
    }
  }

  @Test
  void testAuthorizationCodeUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .userBehavior(UserBehavior.builder().emulateFailure(true).build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .isInstanceOf(OAuth2Exception.class)
          .hasMessageContaining("OAuth2 request failed: Invalid request");
    }
  }

  @CartesianTest
  void testDeviceCode(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @Test
  void testDeviceCodeTimeout() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .timeout(Duration.ofMillis(10))
                .forceInactiveUser(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .hasMessage("Timed out waiting for an access token")
          .cause()
          .isInstanceOf(TimeoutException.class);
    }
  }

  @Test
  void testDeviceCodeUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .timeout(Duration.ofSeconds(1))
                .userBehavior(UserBehavior.builder().emulateFailure(true).build())
                .build();
        OAuth2Agent agent = env.newAgent()) {
      // A user failure means the flow will never complete, so a timeout is expected
      soft.assertThatThrownBy(agent::authenticate)
          .hasMessage("Timed out waiting for an access token")
          .cause()
          .isInstanceOf(TimeoutException.class);
    }
  }

  @CartesianTest
  void testRefreshToken(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokenLifespan)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokenLifespan(returnRefreshTokenLifespan)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult firstTokens = agent.authenticateInternal();
      TokensResult refreshedTokens =
          agent.refreshCurrentTokens(firstTokens).toCompletableFuture().get();
      assertTokensResult(
          refreshedTokens, "access_refreshed", "refresh_refreshed", returnRefreshTokenLifespan);
    }
  }

  @Test
  void testRefreshTokenMustFetchNewTokens() {
    try (TestEnvironment env = TestEnvironment.builder().build();
        OAuth2Agent agent = env.newAgent()) {
      // no refresh token
      TokensResult currentTokens =
          TokensResult.of(
              new Tokens(new BearerAccessToken("access_initial"), null),
              TestConstants.NOW,
              Map.of());
      assertThat(agent.refreshCurrentTokens(currentTokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
      // refresh token with no lifespan => assume not expired
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken("access_initial"), new RefreshToken("refresh_initial")),
              TestConstants.NOW,
              Map.of());
      assertThat(agent.refreshCurrentTokens(currentTokens)).isNotCompletedExceptionally();
      // refresh token with lifespan zero => assume not expired
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken("access_initial"), new RefreshToken("refresh_initial")),
              TestConstants.NOW,
              Map.of("refresh_expires_in", 0L));
      assertThat(agent.refreshCurrentTokens(currentTokens)).isNotCompletedExceptionally();
      // refresh token with lifespan non-zero but expired => assume expired
      // (note: the safety window is 5s)
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken("access_initial"), new RefreshToken("refresh_initial")),
              TestConstants.NOW,
              Map.of("refresh_expires_in", 5L));
      assertThat(agent.refreshCurrentTokens(currentTokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
      // refresh token with lifespan non-zero and not expired => assume not expired
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken("access_initial"), new RefreshToken("refresh_initial")),
              TestConstants.NOW,
              Map.of("refresh_expires_in", 6L));
      assertThat(agent.refreshCurrentTokens(currentTokens)).isNotCompletedExceptionally();
    }
  }

  @CartesianTest
  void testTokenExchangeStaticSubjectActor(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
      if (returnRefreshTokens) {
        currentTokens = agent.refreshCurrentTokens(currentTokens).toCompletableFuture().get();
        assertTokensResult(currentTokens, "access_refreshed", "refresh_refreshed");
      }
    }
  }

  @CartesianTest
  void testTokenExchangeDynamicSubject(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType subjectGrantType)
      throws InterruptedException, ExecutionException {
    assumeTrue(
        !subjectGrantType.equals(GrantType.CLIENT_CREDENTIALS)
            || !authenticationMethod.equals(ClientAuthenticationMethod.NONE));
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .httpClientType(httpClientType)
                .subjectToken(null)
                .subjectGrantType(subjectGrantType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(tokens, "access_refreshed", "refresh_refreshed");
      }
    }
  }

  @CartesianTest
  void testTokenExchangeDynamicActor(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(excludes = "urn:ietf:params:oauth:grant-type:token-exchange")
          GrantType actorGrantType)
      throws InterruptedException, ExecutionException {
    assumeTrue(
        !actorGrantType.equals(GrantType.CLIENT_CREDENTIALS)
            || !authenticationMethod.equals(ClientAuthenticationMethod.NONE));
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .httpClientType(httpClientType)
                .actorToken(null)
                .actorGrantType(actorGrantType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(tokens, "access_refreshed", "refresh_refreshed");
      }
    }
  }

  @Test
  void testTokenExchangeSubjectUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .subjectToken(new TypelessAccessToken("WrongSubjectToken"))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(throwable(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .satisfies(
              r -> {
                soft.assertThat(r.getCode()).isEqualTo("invalid_request");
                soft.assertThat(r.getDescription()).contains("Invalid request");
              });
    }
  }

  @Test
  void testTokenExchangeActorUnauthorized() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .actorToken(new TypelessAccessToken("WrongActorToken"))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(throwable(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .satisfies(
              r -> {
                soft.assertThat(r.getCode()).isEqualTo("invalid_request");
                soft.assertThat(r.getDescription()).contains("Invalid request");
              });
    }
  }

  @CartesianTest
  @EnumSource(HttpClientType.class)
  void testStaticToken(@Enum HttpClientType httpClientType) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .httpClientType(httpClientType)
                .token(new TypelessAccessToken("access_initial"))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      assertAccessToken(tokens.getTokens().getAccessToken(), "access_initial", 0);
      // Cannot refresh a static token as there is no refresh token
      soft.assertThat(agent.refreshCurrentTokens(tokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
    }
  }

  @Test
  void testSsl(@TempDir Path tempDir) {
    Path dest = Paths.get(tempDir.toString(), "mockserver.p12");
    CryptoUtils.copyMockserverKeystore(dest);
    try (TestEnvironment env =
            TestEnvironment.builder()
                .ssl(true)
                .httpClientType(HttpClientType.APACHE)
                .sslTrustStorePath(dest)
                .sslTrustStorePassword("s3cr3t")
                .sslProtocols("TLSv1.3,TLSv1.2")
                .sslCipherSuites(
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
                        + "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
                        + "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
                        + "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertThatCode(agent::authenticate).doesNotThrowAnyException();
    }
  }

  @Test
  void testSslTrustAll() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .ssl(true)
                .httpClientType(HttpClientType.APACHE)
                .sslTrustAll(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertThatCode(agent::authenticate).doesNotThrowAnyException();
    }
  }

  @Test
  void testProxy() {
    try (ClientAndServer proxyServer = ClientAndServer.startClientAndServer();
        TestEnvironment env =
            TestEnvironment.builder()
                .httpClientType(HttpClientType.APACHE)
                .proxyHost("localhost")
                .proxyPort(proxyServer.getLocalPort())
                .build()) {

      proxyServer
          .when(request())
          .forward(
              HttpForward.forward()
                  .withHost("localhost")
                  .withPort(env.getServerRootUrl().getPort())
                  .withScheme(HttpForward.Scheme.HTTP));

      try (OAuth2Agent agent = env.newAgent()) {
        TokensResult currentTokens = agent.authenticateInternal();
        assertTokensResult(currentTokens, "access_initial", null);
      }

      proxyServer.verify(request().withMethod("POST"), atLeast(1));
    }
  }

  @Test
  void testProxyAuthentication() {
    try (ClientAndServer proxyServer = ClientAndServer.startClientAndServer();
        TestEnvironment env =
            TestEnvironment.builder()
                .httpClientType(HttpClientType.APACHE)
                .proxyHost("localhost")
                .proxyPort(proxyServer.getLocalPort())
                .proxyUsername("testuser")
                .proxyPassword("testpass")
                .build()) {

      String authHeader = CryptoUtils.encodeBasicHeader("testuser", "testpass");

      proxyServer
          .when(request().withHeader("Proxy-Authorization", authHeader))
          .forward(
              HttpForward.forward()
                  .withHost("localhost")
                  .withPort(env.getServerRootUrl().getPort())
                  .withScheme(HttpForward.Scheme.HTTP));

      proxyServer
          .when(request())
          .respond(
              response()
                  .withStatusCode(407)
                  .withHeader("Proxy-Authenticate", "Basic realm=\"proxy\""));

      try (OAuth2Agent agent = env.newAgent()) {
        TokensResult currentTokens = agent.authenticateInternal();
        assertTokensResult(currentTokens, "access_initial", null);
      }

      proxyServer.verify(
          request().withMethod("POST").withHeader("Proxy-Authorization", authHeader), atLeast(1));
    }
  }

  /**
   * Tests copying an agent before and after closing the original agent. The typical use case for
   * copying an agent is when reusing an init session as a catalog session, so the init session is
   * already closed when it's copied. But we also want to test the case where the init session is
   * not yet closed when it's copied, since nothing in the API prevents that.
   */
  @Test
  void testCopyAfterSuccessfulAuth() throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .subjectToken(null)
                .actorToken(null)
                .subjectGrantType(GrantType.AUTHORIZATION_CODE)
                .build();
        OAuth2Agent agent1 = env.newAgent()) {
      TokensResult tokens = agent1.authenticateInternal();
      assertTokensResult(tokens, "access_initial", "refresh_initial");
      // 1) Test copy before close
      try (OAuth2Agent agent2 = agent1.copy()) {
        // Should have the same tokens instance
        soft.assertThat(agent2.authenticateInternal()).isSameAs(tokens);
        // Now close agent1
        agent1.close();
        // Should still have the same tokens instance, and not throw
        soft.assertThat(agent2.authenticateInternal()).isSameAs(tokens);
        // Should have a token refresh future
        soft.assertThat(agent2).extracting("tokenRefreshFuture").isNotNull();
        // Should be able to refresh tokens
        TokensResult refreshedTokens =
            agent2.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(refreshedTokens, "access_refreshed", "refresh_refreshed");
        // Should be able to fetch new tokens
        TokensResult newTokens = agent2.fetchNewTokens().toCompletableFuture().get();
        assertTokensResult(newTokens, "access_initial", "refresh_initial");
      }
      // 2) Test copy after close
      try (OAuth2Agent agent3 = agent1.copy()) {
        // Should have the same tokens instance
        soft.assertThat(agent3.authenticateInternal()).isSameAs(tokens);
        // Should have a token refresh future
        soft.assertThat(agent3).extracting("tokenRefreshFuture").isNotNull();
        // Should be able to refresh tokens
        TokensResult refreshedTokens =
            agent3.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(refreshedTokens, "access_refreshed", "refresh_refreshed");
        // Should be able to fetch new tokens
        TokensResult newTokens = agent3.fetchNewTokens().toCompletableFuture().get();
        assertTokensResult(newTokens, "access_initial", "refresh_initial");
      }
    }
  }

  /**
   * Tests copying an agent before and after closing the original agent, when the original agent
   * failed to authenticate. This is a rather contrived scenario since in practice, a failed init
   * session would cause the catalog initialization to fail; but it's possible in theory, so we
   * should add tests for it.
   */
  @Test
  void testCopyAfterFailedAuth() throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
        TestEnvironment.builder()
            .grantType(GrantType.TOKEN_EXCHANGE)
            .subjectToken(null)
            .actorToken(null)
            .createDefaultExpectations(false)
            .build()) {
      // Emulate success fetching metadata, but failure on initial token fetch
      env.createMetadataDiscoveryExpectations();
      env.createErrorExpectations();
      try (OAuth2Agent agent1 = env.newAgent()) {
        soft.assertThatThrownBy(agent1::authenticateInternal).isInstanceOf(OAuth2Exception.class);
        // Restore expectations so that copied agents can fetch tokens
        env.reset();
        env.createExpectations();
        // 1) Test copy before close
        try (OAuth2Agent agent2 = agent1.copy()) {
          // Should be able to fetch tokens even if the original agent failed
          soft.assertThat(agent2.authenticateInternal()).isNotNull();
          // Now close agent1
          agent1.close();
          // Should still have tokens
          TokensResult tokens = agent2.authenticateInternal();
          assertTokensResult(tokens, "access_initial", "refresh_initial");
          soft.assertThat(tokens).isNotNull();
          // Should have a token refresh future
          soft.assertThat(agent2).extracting("tokenRefreshFuture").isNotNull();
          // Should be able to refresh tokens
          TokensResult refreshedTokens =
              agent2.refreshCurrentTokens(tokens).toCompletableFuture().get();
          assertTokensResult(refreshedTokens, "access_refreshed", "refresh_refreshed");
          // Should be able to fetch new tokens
          TokensResult newTokens = agent2.fetchNewTokens().toCompletableFuture().get();
          assertTokensResult(newTokens, "access_initial", "refresh_initial");
        }
        // 2) Test copy after close
        try (OAuth2Agent agent3 = agent1.copy()) {
          // Should be able to fetch tokens even if the original agent failed
          TokensResult tokens = agent3.authenticateInternal();
          assertTokensResult(tokens, "access_initial", "refresh_initial");
          soft.assertThat(tokens).isNotNull();
          // Should be able to refresh tokens
          TokensResult refreshedTokens =
              agent3.refreshCurrentTokens(tokens).toCompletableFuture().get();
          assertTokensResult(refreshedTokens, "access_refreshed", "refresh_refreshed");
          // Should be able to fetch new tokens
          TokensResult newTokens = agent3.fetchNewTokens().toCompletableFuture().get();
          assertTokensResult(newTokens, "access_initial", "refresh_initial");
        }
      }
    }
  }

  @Test
  void testSleepWakeUp() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor);

    try (TestEnvironment env =
            TestEnvironment.builder().grantType(GrantType.PASSWORD).executor(executor).build();
        OAuth2Agent agent = env.newAgent()) {

      // should fetch the initial token
      AccessToken token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo("access_initial");

      // emulate executor running the scheduled renewal task
      currentRenewalTask.get().run();

      // should have refreshed the token
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo("access_refreshed");

      Duration idleTimeout =
          env.getOAuth2Config().getTokenRefreshConfig().getIdleTimeout().plusSeconds(1);

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call and schedule a token refresh
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo("access_refreshed");
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      // again
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call
      // and refresh tokens immediately because the current ones are expired
      ((TestClock) env.getClock()).plus(TestConstants.ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo("access_refreshed");
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
    }
  }

  @Test
  void testExecutionRejectedOnInitialTokenFetch() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    // First token fetch will throw
    doThrow(RejectedExecutionException.class).when(executor).execute(any(Runnable.class));
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor);

    // If the executor rejects the initial token fetch, a call to authenticate()
    // throws RejectedExecutionException immediately.

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .executor(executor)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      soft.assertThatThrownBy(agent::authenticate)
          .hasCauseInstanceOf(RejectedExecutionException.class);

      // Next token fetch will succeed
      mockExecutorExecute(executor);

      // should have scheduled a refresh, when that refresh is executed successfully,
      // agent should recover
      soft.assertThat(currentRenewalTask.get()).isNotNull();
      currentRenewalTask.get().run();
      agent.authenticate();
    }
  }

  @Test
  void testExecutionRejectedOnTokenRefreshes() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor, true);

    // If the executor rejects a scheduled token refresh,
    // sleep mode should be activated; the first call to authenticate()
    // will trigger wake up, then refresh the token immediately (synchronously) if necessary,
    // then schedule a new refresh. If that refresh is rejected again, sleep mode is reactivated.

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .executor(executor)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      // will trigger token fetch (successful), then schedule a refresh, then reject it,
      // then sleep
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(currentRenewalTask.get()).isNull();

      // will wake up, then reject scheduling the next refresh, then sleep again,
      // then return the previously fetched token since it's still valid.
      AccessToken token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(token.getValue()).isEqualTo("access_initial");
      soft.assertThat(currentRenewalTask.get()).isNull();

      // will wake up, then refresh the token immediately (since it's expired),
      // then reject scheduling the next refresh, then sleep again,
      // then return the newly-fetched token
      ((TestClock) env.getClock()).plus(TestConstants.ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(token.getValue()).isEqualTo("access_initial");
      soft.assertThat(currentRenewalTask.get()).isNull();
    }
  }

  @Test
  void testFailureRecovery() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .executor(executor)
                .createDefaultExpectations(false)
                .discoveryEnabled(false)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      // simple failure recovery scenarios

      // Emulate failure on initial token fetch
      // => propagate the error but schedule a refresh ASAP
      env.createErrorExpectations();
      Runnable renewalTask = currentRenewalTask.get();
      soft.assertThat(renewalTask).isNotNull();
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(OAuth2Exception.class);

      // Emulate executor running the scheduled refresh task, then throwing an exception
      // => propagate the error but schedule another refresh
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isNotNull().isNotSameAs(renewalTask);
      renewalTask = currentRenewalTask.get();
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(OAuth2Exception.class);

      // Emulate executor running the scheduled refresh task again, then finally getting tokens
      // => should recover and return initial tokens + schedule next refresh
      env.reset();
      env.createExpectations();
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isNotNull().isNotSameAs(renewalTask);
      renewalTask = currentRenewalTask.get();
      AccessToken token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo("access_initial");

      // failure recovery when in sleep mode

      Duration idleTimeout =
          env.getOAuth2Config().getTokenRefreshConfig().getIdleTimeout().plusSeconds(1);

      // Emulate executor running the scheduled refresh task again, getting tokens,
      // then setting sleeping to true because idle interval is past
      ((TestClock) env.getClock()).plus(idleTimeout);
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isSameAs(renewalTask);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // Emulate waking up when current access token has expired,
      // then getting an error when renewing tokens immediately
      // => should propagate the error but schedule another refresh
      env.reset();
      env.createErrorExpectations();
      ((TestClock) env.getClock()).plus(TestConstants.ACCESS_TOKEN_LIFESPAN);
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(OAuth2Exception.class);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
      soft.assertThat(currentRenewalTask.get()).isNotNull().isNotSameAs(renewalTask);
      renewalTask = currentRenewalTask.get();

      // Emulate executor running the scheduled refresh task again,
      // then getting an error, then setting sleeping to true again because idle interval is past
      ((TestClock) env.getClock()).plus(idleTimeout);
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isSameAs(renewalTask);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThatThrownBy(agent::getCurrentTokens).isInstanceOf(OAuth2Exception.class);

      // Emulate waking up, then fetching tokens immediately because no tokens are available,
      // then scheduling next refresh
      env.reset();
      env.createExpectations();
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
      soft.assertThat(token.getValue()).isEqualTo("access_initial");
      soft.assertThat(currentRenewalTask.get()).isNotSameAs(renewalTask);
      renewalTask = currentRenewalTask.get();

      // Emulate executor running the scheduled refresh task again, refreshing tokens,
      // then setting sleeping to true again because idle interval is past
      ((TestClock) env.getClock()).plus(idleTimeout);
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isSameAs(renewalTask);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // Emulate waking up, then rescheduling a refresh since current token is still valid
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
      soft.assertThat(token.getValue()).isEqualTo("access_refreshed");
      soft.assertThat(currentRenewalTask.get()).isNotSameAs(renewalTask);
    }
  }

  /** Mocks the executor's execute() method to run the task immediately. */
  private static void mockExecutorExecute(ScheduledExecutorService executor) {
    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));
  }

  /** Mocks the executor's schedule() method to capture the scheduled task. */
  private static AtomicReference<Runnable> mockExecutorSchedule(ScheduledExecutorService executor) {
    return mockExecutorSchedule(executor, false);
  }

  /**
   * Mocks the executor's schedule() method to capture the scheduled task, optionally rejecting it.
   */
  private static AtomicReference<Runnable> mockExecutorSchedule(
      ScheduledExecutorService executor, boolean rejectSchedule) {
    AtomicReference<Runnable> task = new AtomicReference<>();
    when(executor.schedule(any(Runnable.class), anyLong(), any()))
        .thenAnswer(
            invocation -> {
              if (rejectSchedule) {
                throw new RejectedExecutionException("test");
              }
              Runnable runnable = invocation.getArgument(0);
              task.set(runnable);
              return mock(ScheduledFuture.class);
            });
    return task;
  }
}

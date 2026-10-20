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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_LIFESPAN;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_REFRESHED;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_REFRESHED;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SUBJECT_TOKEN;
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
import static org.mockserver.model.RegexBody.regex;
import static org.mockserver.verify.VerificationTimes.atLeast;

import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import com.dremio.iceberg.authmgr.oauth2.test.TestClock;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestServer;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.dremio.iceberg.authmgr.oauth2.test.user.UserBehavior;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Enum;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpForward;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.MediaType;

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
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
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
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
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
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
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
          .hasMessage("Token acquisition timed out")
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
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
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
          .hasMessage("Token acquisition timed out")
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
          .hasMessage("Token acquisition timed out")
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
          refreshedTokens,
          ACCESS_TOKEN_REFRESHED,
          REFRESH_TOKEN_REFRESHED,
          returnRefreshTokenLifespan);
    }
  }

  @Test
  void testRefreshTokenMustFetchNewTokens() {
    try (TestEnvironment env = TestEnvironment.builder().build();
        OAuth2Agent agent = env.newAgent()) {
      // no refresh token
      TokensResult currentTokens =
          TokensResult.of(
              new Tokens(new BearerAccessToken(ACCESS_TOKEN_INITIAL), null),
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
                  new BearerAccessToken(ACCESS_TOKEN_INITIAL),
                  new RefreshToken(REFRESH_TOKEN_INITIAL)),
              TestConstants.NOW,
              Map.of());
      assertThat(agent.refreshCurrentTokens(currentTokens)).isNotCompletedExceptionally();
      // refresh token with lifespan zero => assume not expired
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken(ACCESS_TOKEN_INITIAL),
                  new RefreshToken(REFRESH_TOKEN_INITIAL)),
              TestConstants.NOW,
              Map.of("refresh_expires_in", 0L));
      assertThat(agent.refreshCurrentTokens(currentTokens)).isNotCompletedExceptionally();
      // refresh token with lifespan non-zero but expired => assume expired
      // (note: the safety window is 5s)
      currentTokens =
          TokensResult.of(
              new Tokens(
                  new BearerAccessToken(ACCESS_TOKEN_INITIAL),
                  new RefreshToken(REFRESH_TOKEN_INITIAL)),
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
                  new BearerAccessToken(ACCESS_TOKEN_INITIAL),
                  new RefreshToken(REFRESH_TOKEN_INITIAL)),
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
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
      if (returnRefreshTokens) {
        currentTokens = agent.refreshCurrentTokens(currentTokens).toCompletableFuture().get();
        assertTokensResult(currentTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
      }
    }
  }

  @CartesianTest
  void testTokenExchangeDynamicSubject(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(
              excludes = {
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "urn:ietf:params:oauth:grant-type:token-exchange"
              })
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
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(tokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
      }
    }
  }

  @CartesianTest
  void testTokenExchangeDynamicActor(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(
              excludes = {
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "urn:ietf:params:oauth:grant-type:token-exchange"
              })
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
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(tokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
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
  void testJwtBearerStaticAssertion(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .httpClientType(httpClientType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult currentTokens = agent.authenticateInternal();
      assertTokensResult(
          currentTokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
      if (returnRefreshTokens) {
        currentTokens = agent.refreshCurrentTokens(currentTokens).toCompletableFuture().get();
        assertTokensResult(currentTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
      }
    }
  }

  @CartesianTest
  void testJwtBearerDynamicAssertion(
      @Enum HttpClientType httpClientType,
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(
              excludes = {
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "urn:ietf:params:oauth:grant-type:token-exchange"
              })
          GrantType assertionGrantType)
      throws InterruptedException, ExecutionException {
    assumeTrue(
        !assertionGrantType.equals(GrantType.CLIENT_CREDENTIALS)
            || !authenticationMethod.equals(ClientAuthenticationMethod.NONE));
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .httpClientType(httpClientType)
                .assertion(null)
                .assertionGrantType(assertionGrantType)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokensResult(tokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
      }
    }
  }

  @Test
  void testJwtBearerAssertionNotJwt() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .assertion("NotAValidJWT")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .isInstanceOf(RuntimeException.class)
          .hasMessageContaining("Cannot acquire a valid OAuth2 access token")
          .rootCause()
          .isInstanceOf(ParseException.class)
          .hasMessageContaining("The assertion is not a JWT");
    }
  }

  @Test
  void testJwtBearerAssertionInvalid() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .assertion(SUBJECT_TOKEN /* invalid JWT */)
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
                .token(new TypelessAccessToken(ACCESS_TOKEN_INITIAL))
                .build();
        OAuth2Agent agent = env.newAgent()) {
      TokensResult tokens = agent.authenticateInternal();
      assertAccessToken(tokens.getTokens().getAccessToken(), ACCESS_TOKEN_INITIAL, 0);
      // Cannot refresh a static token as there is no refresh token
      soft.assertThat(agent.refreshCurrentTokens(tokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(OAuth2Agent.MustFetchNewTokensException.class);
    }
  }

  @Test
  void testSsl() {
    TestCertificates certs = TestCertificates.instance();
    try (TestEnvironment env =
            TestEnvironment.builder()
                .ssl(true)
                .httpClientType(HttpClientType.APACHE)
                .sslTrustStorePath(certs.getMockServerKeyStore())
                .sslTrustStorePassword(certs.getKeyStorePassword())
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
        assertTokensResult(currentTokens, ACCESS_TOKEN_INITIAL, null);
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

      String authHeader =
          "Basic "
              + Base64.getEncoder()
                  .encodeToString("testuser:testpass".getBytes(StandardCharsets.UTF_8));

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
        assertTokensResult(currentTokens, ACCESS_TOKEN_INITIAL, null);
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
      assertTokensResult(tokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
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
        assertTokensResult(refreshedTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
        // Should be able to fetch new tokens
        TokensResult newTokens = agent2.fetchNewTokens().toCompletableFuture().get();
        assertTokensResult(newTokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
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
        assertTokensResult(refreshedTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
        // Should be able to fetch new tokens
        TokensResult newTokens = agent3.fetchNewTokens().toCompletableFuture().get();
        assertTokensResult(newTokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
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
          assertTokensResult(tokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
          soft.assertThat(tokens).isNotNull();
          // Should have a token refresh future
          soft.assertThat(agent2).extracting("tokenRefreshFuture").isNotNull();
          // Should be able to refresh tokens
          TokensResult refreshedTokens =
              agent2.refreshCurrentTokens(tokens).toCompletableFuture().get();
          assertTokensResult(refreshedTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
          // Should be able to fetch new tokens
          TokensResult newTokens = agent2.fetchNewTokens().toCompletableFuture().get();
          assertTokensResult(newTokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
        }
        // 2) Test copy after close
        try (OAuth2Agent agent3 = agent1.copy()) {
          // Should be able to fetch tokens even if the original agent failed
          TokensResult tokens = agent3.authenticateInternal();
          assertTokensResult(tokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
          soft.assertThat(tokens).isNotNull();
          // Should be able to refresh tokens
          TokensResult refreshedTokens =
              agent3.refreshCurrentTokens(tokens).toCompletableFuture().get();
          assertTokensResult(refreshedTokens, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED);
          // Should be able to fetch new tokens
          TokensResult newTokens = agent3.fetchNewTokens().toCompletableFuture().get();
          assertTokensResult(newTokens, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL);
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
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);

      // emulate executor running the scheduled renewal task
      currentRenewalTask.get().run();

      // should have refreshed the token
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);

      Duration idleTimeout =
          env.getOAuth2Config().getTokenRefreshConfig().getIdleTimeout().plusSeconds(1);

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call and schedule a token refresh
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      // again
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call
      // and refresh tokens immediately because the current ones are expired
      ((TestClock) env.getClock()).plus(ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);
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
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(currentRenewalTask.get()).isNull();

      // will wake up, then refresh the token immediately (since it's expired),
      // then reject scheduling the next refresh, then sleep again,
      // then return the newly-fetched token
      ((TestClock) env.getClock()).plus(ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
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
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);

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
      // => should keep old tokens and schedule another refresh
      env.reset();
      env.createErrorExpectations();
      ((TestClock) env.getClock()).plus(ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED); // old tokens kept
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
      soft.assertThat(currentRenewalTask.get()).isNotNull().isNotSameAs(renewalTask);
      renewalTask = currentRenewalTask.get();

      // Emulate executor running the scheduled refresh task again,
      // then getting an error, then setting sleeping to true again because idle interval is past
      ((TestClock) env.getClock()).plus(idleTimeout);
      renewalTask.run();
      soft.assertThat(currentRenewalTask.get()).isSameAs(renewalTask);
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      token = agent.getCurrentTokens().getTokens().getAccessToken();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED); // old tokens still kept

      // Emulate waking up; old tokens are available so renewal refreshes them,
      // then scheduling next refresh
      env.reset();
      env.createExpectations();
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);
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
      soft.assertThat(token.getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);
      soft.assertThat(currentRenewalTask.get()).isNotSameAs(renewalTask);
    }
  }

  @ParameterizedTest
  @EnumSource(HttpClientType.class)
  void testRefreshRetriedOnTransientError(HttpClientType httpClientType) {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    List<Duration> delays = new ArrayList<>();
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor, delays);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .httpClientType(httpClientType)
                .executor(executor)
                .discoveryEnabled(false)
                .tokenRefreshMaxRetries(2)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      TestClock clock = (TestClock) env.getClock();
      Duration normalDelay = ACCESS_TOKEN_LIFESPAN.minusSeconds(5);

      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(delays).containsExactly(normalDelay);

      // The token endpoint now fails refreshes with a transient error, while the initial grant
      // would still succeed. The access token expires before the scheduled refresh runs.
      env.reset();
      AtomicInteger passwordRequests =
          respondToTokenRequests(env, "password", tokenResponse("access_fallback"));
      AtomicInteger refreshRequests =
          respondToTokenRequests(env, "refresh_token", response().withStatusCode(503));
      clock.plus(ACCESS_TOKEN_LIFESPAN);
      agent.authenticate(); // keep the agent from going idle

      // 1st and 2nd failures: no fallback to the initial grant, old tokens kept, and the refresh is
      // retried with an exponential backoff
      currentRenewalTask.get().run();
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(refreshRequests).hasValue(2);
      soft.assertThat(passwordRequests).hasValue(0);
      soft.assertThat(delays)
          .containsExactly(normalDelay, Duration.ofSeconds(5), Duration.ofSeconds(10));

      // 3rd failure: retry budget exhausted, fall back to the initial grant;
      // on success, the backoff is reset
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo("access_fallback");
      soft.assertThat(refreshRequests).hasValue(3);
      soft.assertThat(passwordRequests).hasValue(1);
      soft.assertThat(delays).last().isEqualTo(normalDelay);

      // The fallback reset the retry budget: the next transient failure is retried again
      clock.plus(ACCESS_TOKEN_LIFESPAN);
      agent.authenticate(); // keep the agent from going idle
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo("access_fallback");
      soft.assertThat(refreshRequests).hasValue(4);
      soft.assertThat(passwordRequests).hasValue(1);
      soft.assertThat(delays).last().isEqualTo(Duration.ofSeconds(5));
    }
  }

  @Test
  void testRefreshFallbackOnNonTransientError() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .executor(executor)
                .discoveryEnabled(false)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);

      // The refresh token was revoked: fall back to the initial grant right away
      env.reset();
      AtomicInteger passwordRequests =
          respondToTokenRequests(env, "password", tokenResponse("access_fallback"));
      AtomicInteger refreshRequests =
          respondToTokenRequests(
              env,
              "refresh_token",
              response()
                  .withStatusCode(400)
                  .withContentType(MediaType.APPLICATION_JSON)
                  .withBody("{\"error\":\"invalid_grant\"}"));

      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo("access_fallback");
      soft.assertThat(refreshRequests).hasValue(1);
      soft.assertThat(passwordRequests).hasValue(1);
    }
  }

  @ParameterizedTest
  @EnumSource(HttpClientType.class)
  void testRefreshRateLimited(HttpClientType httpClientType) {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    List<Duration> delays = new ArrayList<>();
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor, delays);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .httpClientType(httpClientType)
                .executor(executor)
                .discoveryEnabled(false)
                // rate-limited refreshes never fall back, even with retries disabled
                .tokenRefreshMaxRetries(0)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      TestClock clock = (TestClock) env.getClock();
      Duration normalDelay = ACCESS_TOKEN_LIFESPAN.minusSeconds(5);

      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      clock.plus(ACCESS_TOKEN_LIFESPAN);
      agent.authenticate(); // keep the agent from going idle

      // Rate-limited with Retry-After in seconds: no fallback, next renewal after that delay
      env.reset();
      AtomicInteger passwordRequests =
          respondToTokenRequests(env, "password", tokenResponse("access_fallback"));
      AtomicInteger refreshRequests =
          respondToTokenRequests(env, "refresh_token", rateLimitedResponse("120"));
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(refreshRequests).hasValue(1);
      soft.assertThat(passwordRequests).hasValue(0);
      soft.assertThat(delays).last().isEqualTo(Duration.ofSeconds(120));

      // Rate-limited with Retry-After as an HTTP-date far in the future: delay capped
      env.reset();
      passwordRequests = respondToTokenRequests(env, "password", tokenResponse("access_fallback"));
      String date =
          DateTimeFormatter.RFC_1123_DATE_TIME.format(
              clock.instant().plus(Duration.ofDays(1)).atZone(ZoneOffset.UTC));
      refreshRequests = respondToTokenRequests(env, "refresh_token", rateLimitedResponse(date));
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(refreshRequests).hasValue(1);
      soft.assertThat(passwordRequests).hasValue(0);
      soft.assertThat(delays).last().isEqualTo(OAuth2Agent.MAX_RETRY_AFTER);

      // The server recovers
      env.reset();
      env.createExpectations();
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_REFRESHED);
      soft.assertThat(delays).last().isEqualTo(normalDelay);
    }
  }

  @Test
  void testInitialFetchBackoff() {

    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    mockExecutorExecute(executor);
    List<Duration> delays = new ArrayList<>();
    AtomicReference<Runnable> currentRenewalTask = mockExecutorSchedule(executor, delays);

    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .executor(executor)
                .createDefaultExpectations(false)
                .discoveryEnabled(false)
                .build();
        OAuth2Agent agent = env.newAgent()) {

      env.createErrorExpectations();
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(OAuth2Exception.class);
      for (int i = 0; i < 6; i++) {
        currentRenewalTask.get().run();
      }
      soft.assertThatThrownBy(agent::authenticate).isInstanceOf(OAuth2Exception.class);
      // backoff doubles with each failure, starting at the min refresh delay, up to MAX_BACKOFF
      soft.assertThat(delays)
          .containsExactly(
              Duration.ofSeconds(5),
              Duration.ofSeconds(10),
              Duration.ofSeconds(20),
              Duration.ofSeconds(40),
              OAuth2Agent.MAX_BACKOFF,
              OAuth2Agent.MAX_BACKOFF,
              OAuth2Agent.MAX_BACKOFF);

      // The server recovers: the backoff is reset
      env.reset();
      env.createExpectations();
      currentRenewalTask.get().run();
      soft.assertThat(agent.authenticate().getValue()).isEqualTo(ACCESS_TOKEN_INITIAL);
      soft.assertThat(delays).last().isEqualTo(ACCESS_TOKEN_LIFESPAN.minusSeconds(5));
    }
  }

  @Test
  void testIsTransientError() {
    soft.assertThat(OAuth2Agent.isTransientError(new TimeoutException())).isTrue();
    soft.assertThat(OAuth2Agent.isTransientError(new IOException())).isTrue();
    soft.assertThat(
            OAuth2Agent.isTransientError(
                new CompletionException(new RuntimeException(new IOException()))))
        .isTrue();
    soft.assertThat(OAuth2Agent.isTransientError(new RuntimeException())).isFalse();
    soft.assertThat(OAuth2Agent.isTransientError(new IllegalStateException())).isFalse();
  }

  @Test
  void testApplyAuthenticationBearer() {
    try (TestEnvironment env = TestEnvironment.builder().build();
        OAuth2Agent agent = env.newAgent()) {

      Map<String, String> headers = new LinkedHashMap<>();
      agent.applyAuthentication(
          "GET", URI.create("https://rs.example.com/warehouse1"), headers::put);

      soft.assertThat(headers).containsOnlyKeys("Authorization");
      soft.assertThat(headers).containsEntry("Authorization", "Bearer " + ACCESS_TOKEN_INITIAL);
    }
  }

  @Test
  void testApplyAuthenticationDpop() throws Exception {
    try (TestEnvironment env =
            TestEnvironment.builder().dpopEnabled(true).dpopAlgorithm(JWSAlgorithm.ES256).build();
        OAuth2Agent agent = env.newAgent()) {

      URI rsUri = URI.create("https://rs.example.com/warehouse1");
      Map<String, String> headers = new LinkedHashMap<>();
      agent.applyAuthentication("GET", rsUri, headers::put);

      soft.assertThat(headers).containsOnlyKeys("Authorization", "DPoP");
      soft.assertThat(headers).containsEntry("Authorization", "DPoP " + ACCESS_TOKEN_INITIAL);

      SignedJWT proof = SignedJWT.parse(headers.get("DPoP"));
      JWTClaimsSet claims = proof.getJWTClaimsSet();
      soft.assertThat(claims.getStringClaim("htm")).isEqualTo("GET");
      soft.assertThat(claims.getStringClaim("htu")).isEqualTo(rsUri.toString());

      byte[] expectedHash =
          MessageDigest.getInstance("SHA-256")
              .digest(ACCESS_TOKEN_INITIAL.getBytes(StandardCharsets.US_ASCII));
      soft.assertThat(claims.getStringClaim("ath"))
          .isEqualTo(Base64URL.encode(expectedHash).toString());
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
   * Mocks the executor's schedule() method to capture the scheduled task, and to record its delay.
   */
  private static AtomicReference<Runnable> mockExecutorSchedule(
      ScheduledExecutorService executor, List<Duration> delays) {
    return mockExecutorSchedule(executor, false, delays);
  }

  /**
   * Mocks the executor's schedule() method to capture the scheduled task, optionally rejecting it.
   */
  private static AtomicReference<Runnable> mockExecutorSchedule(
      ScheduledExecutorService executor, boolean rejectSchedule) {
    return mockExecutorSchedule(executor, rejectSchedule, new ArrayList<>());
  }

  private static AtomicReference<Runnable> mockExecutorSchedule(
      ScheduledExecutorService executor, boolean rejectSchedule, List<Duration> delays) {
    AtomicReference<Runnable> task = new AtomicReference<>();
    when(executor.schedule(any(Runnable.class), anyLong(), any()))
        .thenAnswer(
            invocation -> {
              if (rejectSchedule) {
                throw new RejectedExecutionException("test");
              }
              Runnable runnable = invocation.getArgument(0);
              long delay = invocation.getArgument(1);
              TimeUnit unit = invocation.getArgument(2);
              task.set(runnable);
              delays.add(Duration.ofMillis(unit.toMillis(delay)));
              return mock(ScheduledFuture.class);
            });
    return task;
  }

  private static HttpRequest tokenRequest(TestEnvironment env, String grantType) {
    return request()
        .withMethod("POST")
        .withPath(env.getTokenEndpoint().getPath())
        .withBody(regex(".*grant_type=" + grantType + ".*"));
  }

  /**
   * Responds to token requests of the given grant type with the given response, and returns a
   * counter of such requests. (MockServer's own request verification is unreliable here, as its
   * event log is shared by all tests and capped.)
   */
  private static AtomicInteger respondToTokenRequests(
      TestEnvironment env, String grantType, HttpResponse response) {
    AtomicInteger count = new AtomicInteger();
    TestServer.getInstance()
        .when(tokenRequest(env, grantType))
        .respond(
            request -> {
              count.incrementAndGet();
              return response;
            });
    return count;
  }

  private static HttpResponse tokenResponse(String accessToken) {
    return response()
        .withContentType(MediaType.APPLICATION_JSON)
        .withBody(
            String.format(
                "{\"access_token\":\"%s\",\"token_type\":\"bearer\",\"expires_in\":%d,"
                    + "\"refresh_token\":\"%s\"}",
                accessToken, ACCESS_TOKEN_LIFESPAN.toSeconds(), REFRESH_TOKEN_INITIAL));
  }

  private static HttpResponse rateLimitedResponse(String retryAfter) {
    return response()
        .withStatusCode(429)
        .withHeader("Retry-After", retryAfter)
        .withContentType(MediaType.APPLICATION_JSON)
        .withBody("{\"error\":\"slow_down\"}");
  }
}

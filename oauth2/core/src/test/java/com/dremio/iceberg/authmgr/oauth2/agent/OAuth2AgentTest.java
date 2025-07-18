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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertAccessToken;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;
import static org.assertj.core.api.InstanceOfAssertFactories.ATOMIC_BOOLEAN;
import static org.assertj.core.api.InstanceOfAssertFactories.throwable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent.MustFetchNewTokensException;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.TestClock;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.user.KeycloakAuthCodeUserEmulator;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.iceberg.exceptions.RESTException;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@ExtendWith(SoftAssertionsExtension.class)
class OAuth2AgentTest {

  @InjectSoftAssertions protected SoftAssertions soft;

  @Test
  void testClientCredentials() {
    try (TestEnvironment env = TestEnvironment.builder().build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(agent.getCurrentTokens(), "access_initial", null);
    }
  }

  @Test
  void testClientCredentialsIcebergDialect() {
    try (TestEnvironment env = TestEnvironment.builder().dialect(Dialect.ICEBERG_REST).build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(agent.getCurrentTokens(), "access_initial", null);
    }
  }

  @Test
  void testClientCredentialsUnauthorized() {
    try (TestEnvironment env = TestEnvironment.builder().clientId("WrongClient").build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(throwable(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorResponse)
          .satisfies(
              r -> {
                soft.assertThat(r.type()).isEqualTo("invalid_request");
                soft.assertThat(r.message()).contains("Invalid request");
              });
    }
  }

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void testPassword(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.PASSWORD)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(
          agent.getCurrentTokens(),
          "access_initial",
          returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void testTokenExchange(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(
          agent.getCurrentTokens(),
          "access_initial",
          returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void testAuthorizationCode(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(
          agent.getCurrentTokens(),
          "access_initial",
          returnRefreshTokens ? "refresh_initial" : null);
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
  void testAuthorizationCodeWrongCode() {
    try (TestEnvironment env =
            TestEnvironment.builder().grantType(GrantType.AUTHORIZATION_CODE).build();
        OAuth2Agent agent = env.newAgent()) {
      ((KeycloakAuthCodeUserEmulator) env.getUser()).overrideAuthorizationCode("wrong-code", 401);
      soft.assertThatThrownBy(agent::authenticate)
          .isInstanceOf(OAuth2Exception.class)
          .hasMessageContaining("OAuth2 request failed: Invalid request");
    }
  }

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void testDeviceCode(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      agent.authenticate();
      assertTokens(
          agent.getCurrentTokens(),
          "access_initial",
          returnRefreshTokens ? "refresh_initial" : null);
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

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void testRefreshToken(boolean privateClient, boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .forceInactiveUser(true)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens currentTokens =
          Tokens.of(
              AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME),
              RefreshToken.of("refresh_initial", REFRESH_TOKEN_EXPIRATION_TIME));
      Tokens tokens = agent.refreshCurrentTokens(currentTokens).toCompletableFuture().get();
      assertTokens(
          tokens,
          "access_refreshed",
          returnRefreshTokens ? "refresh_refreshed" : "refresh_initial");
    }
  }

  @Test
  void testRefreshTokenIcebergDialect() throws InterruptedException, ExecutionException {
    try (TestEnvironment env = TestEnvironment.builder().dialect(Dialect.ICEBERG_REST).build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens currentTokens =
          Tokens.of(AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME), null);
      Tokens tokens = agent.refreshCurrentTokens(currentTokens).toCompletableFuture().get();
      assertTokens(tokens, "access_refreshed", null);
    }
  }

  @Test
  void testRefreshTokenExpired() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .forceInactiveUser(true)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens currentTokens =
          Tokens.of(
              AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME),
              RefreshToken.of("refresh_initial", REFRESH_TOKEN_EXPIRATION_TIME));
      Tokens tokens =
          Tokens.of(
              currentTokens.getAccessToken(),
              RefreshToken.of("refresh_expired", TestConstants.NOW.minusSeconds(1)));
      soft.assertThat(agent.refreshCurrentTokens(tokens))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(MustFetchNewTokensException.class);
    }
  }

  @ParameterizedTest
  @CsvSource({
    "true,  false, CLIENT_CREDENTIALS",
    "true,  true,  PASSWORD",
    "true,  false, PASSWORD",
    "false, true,  PASSWORD",
    "false, false, PASSWORD",
    "true,  true,  AUTHORIZATION_CODE",
    "true,  false, AUTHORIZATION_CODE",
    "false, true,  AUTHORIZATION_CODE",
    "false, false, AUTHORIZATION_CODE",
    "true,  true,  DEVICE_CODE",
    "true,  false, DEVICE_CODE",
    "false, true,  DEVICE_CODE",
    "false, false, DEVICE_CODE",
  })
  void testImpersonate(boolean privateClient, boolean returnRefreshTokens, GrantType grantType)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .subjectToken(null)
                .subjectGrantType(grantType)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens tokens = agent.fetchNewTokens().toCompletableFuture().get();
      assertTokens(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
      if (returnRefreshTokens) {
        tokens = agent.refreshCurrentTokens(tokens).toCompletableFuture().get();
        assertTokens(tokens, "access_refreshed", "refresh_refreshed");
      }
    }
  }

  @Test
  void testStaticToken() {
    try (TestEnvironment env = TestEnvironment.builder().token("access_initial").build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens actual = agent.authenticateInternal();
      assertAccessToken(actual.getAccessToken(), "access_initial", null);
      // Cannot refresh a static token with standard dialect
      // as it does not have a refresh token
      soft.assertThat(agent.refreshCurrentTokens(actual))
          .completesExceptionallyWithin(Duration.ofSeconds(10))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(MustFetchNewTokensException.class);
    }
  }

  @Test
  void testStaticTokenIcebergDialect() throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dialect(Dialect.ICEBERG_REST)
                .token("access_initial")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      Tokens actual = agent.authenticateInternal();
      assertAccessToken(actual.getAccessToken(), "access_initial", null);
      // Iceberg dialect is able to refresh a static token without a refresh token
      // (using token exchange with the static token as subject token)
      Tokens refreshed = agent.refreshCurrentTokens(actual).toCompletableFuture().get();
      assertTokens(refreshed, "access_refreshed", null);
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
      Tokens tokens = agent1.authenticateInternal();
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
        assertTokens(
            agent2.refreshCurrentTokens(tokens).toCompletableFuture().get(),
            "access_refreshed",
            "refresh_refreshed");
        // Should be able to fetch new tokens
        soft.assertThat(agent2.fetchNewTokens().toCompletableFuture().get()).isEqualTo(tokens);
      }
      // 2) Test copy after close
      try (OAuth2Agent agent3 = agent1.copy()) {
        // Should have the same tokens instance
        soft.assertThat(agent3.authenticateInternal()).isSameAs(tokens);
        // Should have a token refresh future
        soft.assertThat(agent3).extracting("tokenRefreshFuture").isNotNull();
        // Should be able to refresh tokens
        assertTokens(
            agent3.refreshCurrentTokens(tokens).toCompletableFuture().get(),
            "access_refreshed",
            "refresh_refreshed");
        // Should be able to fetch new tokens
        soft.assertThat(agent3.fetchNewTokens().toCompletableFuture().get()).isEqualTo(tokens);
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
        soft.assertThatThrownBy(agent1::authenticateInternal).isInstanceOf(RESTException.class);
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
          Tokens tokens = agent2.authenticateInternal();
          soft.assertThat(tokens).isNotNull();
          // Should have a token refresh future
          soft.assertThat(agent2).extracting("tokenRefreshFuture").isNotNull();
          // Should be able to refresh tokens
          assertTokens(
              agent2.refreshCurrentTokens(tokens).toCompletableFuture().get(),
              "access_refreshed",
              "refresh_refreshed");
          // Should be able to fetch new tokens
          soft.assertThat(agent2.fetchNewTokens().toCompletableFuture().get()).isEqualTo(tokens);
        }
        // 2) Test copy after close
        try (OAuth2Agent agent3 = agent1.copy()) {
          // Should be able to fetch tokens even if the original agent failed
          Tokens tokens = agent3.authenticateInternal();
          soft.assertThat(tokens).isNotNull();
          // Should be able to refresh tokens
          assertTokens(
              agent3.refreshCurrentTokens(tokens).toCompletableFuture().get(),
              "access_refreshed",
              "refresh_refreshed");
          // Should be able to fetch new tokens
          soft.assertThat(agent3.fetchNewTokens().toCompletableFuture().get()).isEqualTo(tokens);
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
      soft.assertThat(token.getPayload()).isEqualTo("access_initial");

      // emulate executor running the scheduled renewal task
      currentRenewalTask.get().run();

      // should have refreshed the token
      token = agent.authenticate();
      soft.assertThat(token.getPayload()).isEqualTo("access_refreshed");

      Duration idleTimeout =
          env.getAgentSpec().getTokenRefreshConfig().getIdleTimeout().plusSeconds(1);

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call and schedule a token refresh
      token = agent.authenticate();
      soft.assertThat(token.getPayload()).isEqualTo("access_refreshed");
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isFalse();

      // emulate executor running the scheduled renewal task and detecting that the agent is idle
      // again
      ((TestClock) env.getClock()).plus(idleTimeout);
      currentRenewalTask.get().run();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();

      // should exit sleeping mode on next authenticate() call
      // and refresh tokens immediately because the current ones are expired
      ((TestClock) env.getClock()).plus(TestConstants.REFRESH_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(token.getPayload()).isEqualTo("access_initial");
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
            TestEnvironment.builder().grantType(GrantType.PASSWORD).executor(executor).build();
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
            TestEnvironment.builder().grantType(GrantType.PASSWORD).executor(executor).build();
        OAuth2Agent agent = env.newAgent()) {

      // will trigger token fetch (successful), then schedule a refresh, then reject it,
      // then sleep
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(currentRenewalTask.get()).isNull();

      // will wake up, then reject scheduling the next refresh, then sleep again,
      // then return the previously fetched token since it's still valid.
      AccessToken token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(token.getPayload()).isEqualTo("access_initial");
      soft.assertThat(currentRenewalTask.get()).isNull();

      // will wake up, then refresh the token immediately (since it's expired),
      // then reject scheduling the next refresh, then sleep again,
      // then return the newly-fetched token
      ((TestClock) env.getClock()).plus(TestConstants.ACCESS_TOKEN_LIFESPAN);
      token = agent.authenticate();
      soft.assertThat(agent).extracting("sleeping", ATOMIC_BOOLEAN).isTrue();
      soft.assertThat(token.getPayload()).isEqualTo("access_refreshed");
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
      soft.assertThat(token.getPayload()).isEqualTo("access_initial");

      // failure recovery when in sleep mode

      Duration idleTimeout =
          env.getAgentSpec().getTokenRefreshConfig().getIdleTimeout().plusSeconds(1);

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
      soft.assertThat(token.getPayload()).isEqualTo("access_initial");
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
      soft.assertThat(token.getPayload()).isEqualTo("access_refreshed");
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

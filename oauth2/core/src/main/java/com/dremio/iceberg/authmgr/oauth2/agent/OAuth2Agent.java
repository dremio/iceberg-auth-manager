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

import static com.dremio.iceberg.authmgr.oauth2.concurrent.AutoCloseables.cancelOnClose;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.concurrent.Futures;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.flow.Flow;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import jakarta.annotation.Nullable;
import java.io.Closeable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.apache.iceberg.exceptions.RESTException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** An OAuth2 agent that supports fetching and refreshing access tokens. */
public final class OAuth2Agent implements Closeable {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Agent.class);

  private static final Duration MIN_WARN_INTERVAL = Duration.ofSeconds(10);

  private static final CompletableFuture<TokensResult> MUST_FETCH_NEW_TOKENS_FUTURE =
      CompletableFuture.failedFuture(MustFetchNewTokensException.INSTANCE);

  private static final CompletableFuture<Void> DUMMY_COMPLETED_FUTURE =
      CompletableFuture.completedFuture(null);

  private final OAuth2Config config;
  private final ScheduledExecutorService executor;
  private final FlowFactory flowFactory;
  private final String name;
  private final Clock clock;

  private final CompletableFuture<Void> agentAccessed = new CompletableFuture<>();
  private final AtomicBoolean closing = new AtomicBoolean();
  private final AtomicBoolean sleeping = new AtomicBoolean();

  private volatile CompletableFuture<TokensResult> currentTokensFuture;
  private volatile ScheduledFuture<?> tokenRefreshFuture;

  private volatile Instant lastAccess;
  private volatile Instant lastWarn;

  @SuppressWarnings("FutureReturnValueIgnored")
  public OAuth2Agent(OAuth2Config config, OAuth2AgentRuntime runtime) {
    this.config = config;
    this.executor = runtime.getExecutor();
    this.flowFactory = FlowFactory.create(config, runtime);
    name = config.getSystemConfig().getAgentName();
    clock = runtime.getClock();
    lastAccess = clock.instant();
    if (config.getBasicConfig().getToken().isPresent()) {
      var currentTokens = TokensResult.of(config.getBasicConfig().getToken().get());
      currentTokensFuture = CompletableFuture.completedFuture(currentTokens);
      maybeScheduleTokensRenewal(currentTokens);
    } else {
      // when user interaction is not required, token fetch can happen immediately;
      // otherwise, it will be deferred until authenticate() is called the first time,
      // in order to avoid bothering the user with a login prompt before the agent is actually used.
      var requiresUserInteraction =
          ConfigUtils.requiresUserInteraction(config.getBasicConfig().getGrantType());
      CompletableFuture<?> agentReady =
          requiresUserInteraction ? agentAccessed : DUMMY_COMPLETED_FUTURE;
      currentTokensFuture = agentReady.thenComposeAsync((v) -> fetchNewTokens(), executor);
      currentTokensFuture
          .whenComplete(this::log)
          .whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
    }
  }

  /** Copy constructor. */
  @SuppressWarnings("FutureReturnValueIgnored")
  private OAuth2Agent(OAuth2Agent toCopy) {
    LOGGER.debug("[{}] Copying agent", toCopy.name);
    config = toCopy.config;
    executor = toCopy.executor;
    flowFactory = toCopy.flowFactory.copy();
    name = toCopy.name;
    clock = toCopy.clock;
    lastAccess = toCopy.lastAccess;
    lastWarn = toCopy.lastWarn;
    tokenRefreshFuture = null;
    TokensResult currentTokens = Futures.getNow(toCopy.currentTokensFuture);
    currentTokensFuture =
        currentTokens != null
            ? CompletableFuture.completedFuture(currentTokens)
            : CompletableFuture.supplyAsync(this::fetchNewTokens, executor)
                .thenCompose(Function.identity());
    currentTokensFuture.whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
  }

  public OAuth2Config getConfig() {
    return config;
  }

  /**
   * Creates a copy of this agent. The copy will share the same spec, executor and REST client
   * supplier as the original agent, as well as its current tokens, if any. If token refresh is
   * enabled, the copy will create its own token refresh schedule.
   */
  public OAuth2Agent copy() {
    return new OAuth2Agent(this);
  }

  /**
   * Authenticates the client synchronously, waiting for the authentication to complete, and returns
   * the current access token. If the authentication fails, or if the agent is closing, an exception
   * is thrown.
   */
  public AccessToken authenticate() {
    return authenticateInternal().getTokens().getAccessToken();
  }

  /**
   * Authenticates the client asynchronously and returns a future that completes when the
   * authentication completes (either successfully or with an error).
   */
  public CompletionStage<AccessToken> authenticateAsync() {
    return authenticateAsyncInternal()
        .thenApply(TokensResult::getTokens)
        .thenApply(Tokens::getAccessToken);
  }

  /**
   * Same as {@link #authenticate()} but returns the full {@link Tokens} object, including the
   * refresh token if any. Only intended for testing.
   */
  TokensResult authenticateInternal() {
    LOGGER.debug("[{}] Authenticating synchronously", name);
    onAgentAccessed();
    return getCurrentTokens();
  }

  /**
   * Same as {@link #authenticateAsync()} but returns the full {@link Tokens} object, including the
   * refresh token if any. Only intended for testing.
   */
  CompletionStage<TokensResult> authenticateAsyncInternal() {
    LOGGER.debug("[{}] Authenticating asynchronously", name);
    onAgentAccessed();
    return currentTokensFuture;
  }

  TokensResult getCurrentTokens() {
    try {
      Duration timeout = config.getBasicConfig().getTimeout();
      return currentTokensFuture.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    } catch (TimeoutException e) {
      throw new RuntimeException("Timed out waiting for an access token", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Error) {
        throw (Error) cause;
      } else if (cause instanceof OAuth2Exception) {
        throw (OAuth2Exception) cause;
      } else {
        throw new RuntimeException("Cannot acquire a valid OAuth2 access token", cause);
      }
    }
  }

  @Override
  public void close() {
    if (closing.compareAndSet(false, true)) {
      try (flowFactory;
          // Cancelling the agentAccessed future also cancels any pending log messages
          var ignored1 = cancelOnClose(agentAccessed);
          var ignored2 = cancelOnClose(currentTokensFuture);
          var ignored3 = cancelOnClose(tokenRefreshFuture)) {
        LOGGER.debug("[{}] Closing...", name);
      } finally {
        tokenRefreshFuture = null;
        // Don't clear currentTokensFuture, we'll need it in case this agent is copied.
      }
      LOGGER.debug("[{}] Closed", name);
    }
  }

  CompletionStage<TokensResult> fetchNewTokens() {
    Flow flow = flowFactory.createInitialFlow();
    LOGGER.debug("[{}] Fetching new access token using {}", name, flow.getGrantType());
    CompletionStage<TokensResult> newTokensStage = flow.fetchNewTokens();
    // If the flow requires user interaction, update the last access time once the flow completes,
    // in order to better reflect when the agent was actually accessed for the last time.
    // This prevents the agent from going to sleep too early when the user is interacting with it.
    return ConfigUtils.requiresUserInteraction(config.getBasicConfig().getGrantType())
        ? newTokensStage.whenComplete((tokens, error) -> lastAccess = clock.instant())
        : newTokensStage;
  }

  CompletionStage<TokensResult> refreshCurrentTokens(TokensResult currentTokens) {
    RefreshToken refreshToken = currentTokens.getTokens().getRefreshToken();
    if (refreshToken == null
        || currentTokens.isRefreshTokenExpired(
            clock.instant().plus(config.getTokenRefreshConfig().getSafetyWindow()))) {
      LOGGER.debug("[{}] Must fetch new tokens, refresh token is null or expired", name);
      return MUST_FETCH_NEW_TOKENS_FUTURE;
    }
    Flow flow = flowFactory.createTokenRefreshFlow(refreshToken);
    LOGGER.debug("[{}] Refreshing tokens using {}", name, flow.getGrantType());
    return flow.fetchNewTokens();
  }

  private void log(@Nullable TokensResult newTokens, @Nullable Throwable error) {
    if (newTokens != null) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("[{}] Successfully fetched new tokens", name);
        LOGGER.debug(
            "[{}] Access token expiration time: {}",
            name,
            newTokens.getAccessTokenExpirationTime());
      }
    } else if (!closing.get()) {
      if (error instanceof CompletionException) {
        error = error.getCause();
      }
      if (error instanceof RESTException) {
        // Don't include the stack trace if the error is a RESTException,
        // since it's not very useful and just clutters the logs.
        maybeWarn("[{}] Failed to fetch new tokens: {}", name, error.toString());
      } else {
        maybeWarn("[{}] Failed to fetch new tokens", name, error);
      }
    }
  }

  private void maybeScheduleTokensRenewal(@Nullable TokensResult currentTokens) {
    if (!config.getTokenRefreshConfig().isEnabled()) {
      LOGGER.debug(
          "[{}] Agent is not configured to keep tokens refreshed, skipping token renewal", name);
      return;
    }
    if (closing.get()) {
      LOGGER.debug("[{}] Not checking if token renewal is required, agent is closing", name);
      return;
    }
    Instant now = clock.instant();
    Duration timeSinceLastAccess = Duration.between(lastAccess, now);
    boolean idle =
        timeSinceLastAccess.compareTo(config.getTokenRefreshConfig().getIdleTimeout()) > 0;
    LOGGER.debug("[{}] Time since last access: {}, idle: {}", name, timeSinceLastAccess, idle);
    if (idle) {
      maybeSleep();
    } else {
      Duration delay = nextTokenRefresh(currentTokens, now);
      scheduleTokensRenewal(delay);
    }
  }

  private void scheduleTokensRenewal(Duration delay) {
    if (closing.get()) {
      LOGGER.debug("[{}] Not scheduling token renewal, agent is closing", name);
      return;
    }
    LOGGER.debug("[{}] Scheduling token refresh in {}", name, delay);
    try {
      var tokenRefreshFuture =
          executor.schedule(this::renewTokens, delay.toMillis(), TimeUnit.MILLISECONDS);
      this.tokenRefreshFuture = tokenRefreshFuture;
      if (closing.get()) {
        // We raced with close(): cancel the future we just created and clear the field.
        Futures.cancel(tokenRefreshFuture);
        this.tokenRefreshFuture = null;
      }
    } catch (RejectedExecutionException e) {
      if (closing.get()) {
        // We raced with close(), ignore
        return;
      }
      maybeWarn("[{}] Failed to schedule next token renewal, forcibly sleeping", name);
      sleep();
    }
  }

  private Duration nextTokenRefresh(@Nullable TokensResult currentTokens, Instant now) {
    Duration minRefreshDelay = config.getTokenRefreshConfig().getMinRefreshDelay();
    if (currentTokens == null || currentTokens.isAccessTokenExpired(now)) {
      return minRefreshDelay;
    }
    Instant expirationTime = currentTokens.getAccessTokenExpirationTime();
    if (expirationTime == null) {
      Duration defaultLifespan = config.getTokenRefreshConfig().getAccessTokenLifespan();
      maybeWarn(
          "[{}] Access token has no expiration time, assuming lifespan of {}",
          name,
          defaultLifespan);
      expirationTime = now.plus(defaultLifespan);
    }
    Duration delay =
        Duration.between(now, expirationTime)
            .minus(config.getTokenRefreshConfig().getSafetyWindow());
    if (delay.compareTo(minRefreshDelay) < 0) {
      LOGGER.debug("[{}] Next refresh delay was too short: {}", name, delay);
      delay = minRefreshDelay;
    }
    return delay;
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  private void renewTokens() {
    if (closing.get()) {
      LOGGER.debug("[{}] Not renewing tokens, agent is closing", name);
      return;
    }
    CompletableFuture<TokensResult> oldTokensFuture = currentTokensFuture;
    CompletableFuture<TokensResult> newTokensFuture =
        oldTokensFuture
            // try refreshing the current access token, if any
            .thenCompose(this::refreshCurrentTokens)
            // if that fails, try fetching brand-new tokens
            // (note: exceptionallyCompose() would be better but it's Java 12+)
            .handle(
                (tokens, error) ->
                    error == null ? CompletableFuture.completedFuture(tokens) : fetchNewTokens())
            .thenCompose(Function.identity());
    currentTokensFuture = newTokensFuture;
    if (closing.get()) {
      // We raced with close(): cancel the future we just created.
      Futures.cancel(newTokensFuture);
    } else {
      newTokensFuture
          .whenComplete(this::log)
          .whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
    }
  }

  private void maybeSleep() {
    if (!config.getTokenRefreshConfig().isEnabled()) {
      LOGGER.debug(
          "[{}] Agent is not configured to keep tokens refreshed, not entering sleep", name);
      return;
    }
    sleep();
  }

  private void sleep() {
    sleeping.set(true);
    LOGGER.debug("[{}] Sleeping...", name);
  }

  private void onAgentAccessed() {
    if (closing.get()) {
      throw new IllegalStateException("Agent is closing");
    }
    agentAccessed.complete(null);
    Instant now = clock.instant();
    lastAccess = now;
    if (sleeping.compareAndSet(true, false)) {
      wakeUp(now);
    }
  }

  private void wakeUp(Instant now) {
    if (closing.get()) {
      LOGGER.debug("[{}] Not waking up, agent is closing", name);
      return;
    }
    LOGGER.debug("[{}] Waking up...", name);
    TokensResult currentTokens = Futures.getNow(currentTokensFuture);
    if (currentTokens == null
        || currentTokens.isAccessTokenExpired(
            now.plus(config.getTokenRefreshConfig().getSafetyWindow()))) {
      LOGGER.debug("[{}] Refreshing tokens immediately", name);
      renewTokens();
    } else {
      LOGGER.debug("[{}] Tokens are still valid, scheduling refresh", name);
      Duration delay = nextTokenRefresh(currentTokens, now);
      scheduleTokensRenewal(delay);
    }
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  private void maybeWarn(String message, Object... args) {
    if (LOGGER.isWarnEnabled()) {
      Instant now = clock.instant();
      Instant last = lastWarn;
      boolean shouldWarn =
          last == null || Duration.between(last, now).compareTo(MIN_WARN_INTERVAL) > 0;
      if (shouldWarn) {
        // defer logging until the agent is used to avoid confusing log messages appearing
        // before the agent is actually used
        agentAccessed.thenRun(() -> LOGGER.warn(message, args));
        lastWarn = now;
        return;
      }
    }
    LOGGER.debug(message, args);
  }

  static class MustFetchNewTokensException extends RuntimeException {

    private static final MustFetchNewTokensException INSTANCE = new MustFetchNewTokensException();

    private MustFetchNewTokensException() {
      super(null, null, false, false);
    }
  }
}

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

import com.dremio.iceberg.authmgr.oauth2.concurrent.Futures;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.InitialFlow;
import com.dremio.iceberg.authmgr.oauth2.flow.RefreshFlow;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Token;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
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
import java.util.function.Supplier;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.rest.RESTClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** An OAuth2 agent that supports fetching and refreshing access tokens. */
public final class OAuth2Agent implements Closeable {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Agent.class);

  private static final Duration MIN_WARN_INTERVAL = Duration.ofSeconds(10);

  private final OAuth2AgentSpec spec;
  private final ScheduledExecutorService executor;
  private final FlowFactory flowFactory;
  private final String name;
  private final Clock clock;

  private final CompletableFuture<Void> used = new CompletableFuture<>();
  private final AtomicBoolean closing = new AtomicBoolean();
  private final AtomicBoolean sleeping = new AtomicBoolean();

  private volatile CompletableFuture<Tokens> currentTokensFuture;
  private volatile ScheduledFuture<?> tokenRefreshFuture;
  private volatile Instant lastAccess;
  private volatile Instant lastWarn;

  @SuppressWarnings("FutureReturnValueIgnored")
  public OAuth2Agent(
      OAuth2AgentSpec spec,
      ScheduledExecutorService executor,
      Supplier<RESTClient> restClientSupplier) {
    this.spec = spec;
    this.executor = executor;
    this.flowFactory = FlowFactory.of(spec, executor, restClientSupplier);
    name = spec.getRuntimeConfig().getAgentName();
    clock = spec.getRuntimeConfig().getClock();
    lastAccess = clock.instant();
    CompletableFuture<Tokens> currentTokensFuture;
    if (spec.getBasicConfig().getToken().isPresent()) {
      currentTokensFuture =
          CompletableFuture.completedFuture(
              Tokens.of(spec.getBasicConfig().getToken().get(), null));
    } else {
      // when user interaction is not required, token fetch can happen immediately;
      // otherwise, it will be deferred until authenticate() is called the first time,
      // in order to avoid bothering the user with a login prompt before the agent is actually used.
      CompletableFuture<?> ready =
          spec.getBasicConfig().getGrantType().requiresUserInteraction()
              ? used
              : CompletableFuture.completedFuture(null);
      currentTokensFuture = ready.thenComposeAsync((v) -> fetchNewTokens(), executor);
    }
    this.currentTokensFuture = currentTokensFuture;
    currentTokensFuture
        .whenComplete(this::log)
        .whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
  }

  /** Copy constructor. */
  @SuppressWarnings("FutureReturnValueIgnored")
  private OAuth2Agent(OAuth2Agent toCopy) {
    LOGGER.debug("[{}] Copying agent", toCopy.name);
    spec = toCopy.spec;
    executor = toCopy.executor;
    flowFactory = toCopy.flowFactory.copy();
    name = toCopy.name;
    clock = toCopy.clock;
    lastAccess = toCopy.lastAccess;
    lastWarn = toCopy.lastWarn;
    tokenRefreshFuture = null;
    Tokens currentTokens = Futures.getNow(toCopy.currentTokensFuture);
    CompletableFuture<Tokens> currentTokensFuture;
    if (currentTokens != null) {
      currentTokensFuture = CompletableFuture.completedFuture(currentTokens);
    } else {
      currentTokensFuture =
          CompletableFuture.supplyAsync(this::fetchNewTokens, executor)
              .thenCompose(Function.identity());
    }
    this.currentTokensFuture = currentTokensFuture;
    currentTokensFuture.whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
  }

  public OAuth2AgentSpec getSpec() {
    return spec;
  }

  /**
   * Creates a copy of this agent. The copy will share the same spec, executor and REST client
   * supplier as the original agent, as well as its current tokens, if any. If token refresh is
   * enabled, the copy will have its own token refresh schedule.
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
    return authenticateInternal().getAccessToken();
  }

  /**
   * Authenticates the client asynchronously and returns a future that completes when the
   * authentication completes (either successfully or with an error).
   */
  public CompletionStage<AccessToken> authenticateAsync() {
    return authenticateAsyncInternal().thenApply(Tokens::getAccessToken);
  }

  /**
   * Same as {@link #authenticate()} but returns the full {@link Tokens} object, including the
   * refresh token if any. Only intended for testing.
   */
  Tokens authenticateInternal() {
    LOGGER.debug("[{}] Authenticating synchronously", name);
    onAgentAccessed();
    return getCurrentTokens();
  }

  /**
   * Same as {@link #authenticateAsync()} but returns the full {@link Tokens} object, including the
   * refresh token if any. Only intended for testing.
   */
  CompletionStage<Tokens> authenticateAsyncInternal() {
    LOGGER.debug("[{}] Authenticating asynchronously", name);
    onAgentAccessed();
    return currentTokensFuture;
  }

  Tokens getCurrentTokens() {
    try {
      Duration timeout = spec.getBasicConfig().getTimeout();
      return currentTokensFuture
          .toCompletableFuture()
          .get(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    } catch (TimeoutException e) {
      throw new RuntimeException("Timed out waiting for an access token", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Error) {
        throw (Error) cause;
      } else if (cause instanceof RESTException) {
        throw (RESTException) cause;
      } else {
        throw new RuntimeException("Cannot acquire a valid OAuth2 access token", cause);
      }
    }
  }

  @Override
  public void close() {
    if (closing.compareAndSet(false, true)) {
      try (flowFactory;
          // Cancelling the used future also cancels any pending log messages
          var ignored1 = cancelOnClose(used);
          var ignored2 = cancelOnClose(currentTokensFuture);
          var ignored3 = cancelOnClose(tokenRefreshFuture)) {
        LOGGER.debug("[{}] Closing...", name);
      } finally {
        tokenRefreshFuture = null;
        // Don't clear currentTokensStage, we'll need it in case this agent is copied.
      }
      LOGGER.debug("[{}] Closed", name);
    }
  }

  CompletionStage<Tokens> fetchNewTokens() {
    LOGGER.debug(
        "[{}] Fetching new access token using {}", name, spec.getBasicConfig().getGrantType());
    InitialFlow flow = flowFactory.createInitialFlow();
    CompletionStage<Tokens> newTokensStage = flow.fetchNewTokens();
    // If the flow requires user interaction, update the last access time once the flow completes,
    // in order to better reflect when the agent was actually accessed for the last time.
    // This prevents the agent from going to sleep too early when the user is interacting with it.
    return spec.getBasicConfig().getGrantType().requiresUserInteraction()
        ? newTokensStage.whenComplete((tokens, error) -> lastAccess = clock.instant())
        : newTokensStage;
  }

  CompletionStage<Tokens> refreshCurrentTokens(Tokens currentTokens) {
    if (spec.getBasicConfig().getDialect() == Dialect.STANDARD) {
      RefreshToken refreshToken = currentTokens.getRefreshToken();
      Instant nowWithSafety = clock.instant().plus(spec.getTokenRefreshConfig().getSafetyWindow());
      if (refreshToken == null || refreshToken.isExpired(nowWithSafety)) {
        LOGGER.debug("[{}] Must fetch new tokens", name);
        return CompletableFuture.failedFuture(MustFetchNewTokensException.INSTANCE);
      }
    }
    LOGGER.debug("[{}] Refreshing tokens", name);
    RefreshFlow flow = flowFactory.createTokenRefreshFlow();
    return flow.refreshTokens(currentTokens);
  }

  private void log(@Nullable Tokens newTokens, @Nullable Throwable error) {
    if (newTokens != null) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("[{}] Successfully fetched new tokens", name);
        LOGGER.debug(
            "[{}] Access token expiration time: {}",
            name,
            newTokens.getAccessToken().getExpirationTime());
        LOGGER.debug(
            "[{}] Refresh token expiration time: {}",
            name,
            newTokens.getRefreshToken() == null
                ? "null"
                : newTokens.getRefreshToken().getExpirationTime());
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

  private void maybeScheduleTokensRenewal(@Nullable Tokens currentTokens) {
    if (!spec.getTokenRefreshConfig().isEnabled()) {
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
    boolean idle = timeSinceLastAccess.compareTo(spec.getTokenRefreshConfig().getIdleTimeout()) > 0;
    LOGGER.debug("[{}] Time since last access: {}, idle: {}", name, timeSinceLastAccess, idle);
    if (idle) {
      maybeSleep();
    } else {
      Duration delay =
          nextTokenRefresh(currentTokens, now, spec.getTokenRefreshConfig().getMinRefreshDelay());
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

  private Duration nextTokenRefresh(
      @Nullable Tokens currentTokens, Instant now, Duration minRefreshDelay) {
    if (currentTokens == null || currentTokens.getAccessToken().isExpired(now)) {
      return minRefreshDelay;
    }
    Token token = currentTokens.getAccessToken();
    Instant expirationTime = token.getResolvedExpirationTime();
    if (expirationTime == null) {
      Duration defaultLifespan = spec.getTokenRefreshConfig().getAccessTokenLifespan();
      maybeWarn(
          "[{}] Access token has no expiration time, assuming lifespan of {}",
          name,
          defaultLifespan);
      expirationTime = now.plus(defaultLifespan);
    }
    Duration delay =
        Duration.between(now, expirationTime).minus(spec.getTokenRefreshConfig().getSafetyWindow());
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
    CompletableFuture<Tokens> oldTokensFuture = currentTokensFuture;
    CompletableFuture<Tokens> newTokensFuture =
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
    if (!spec.getTokenRefreshConfig().isEnabled()) {
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
    used.complete(null);
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
    Tokens currentTokens = Futures.getNow(currentTokensFuture);
    Duration delay = nextTokenRefresh(currentTokens, now, Duration.ZERO);
    if (delay.compareTo(spec.getTokenRefreshConfig().getMinRefreshDelay()) < 0) {
      LOGGER.debug("[{}] Refreshing tokens immediately", name);
      renewTokens();
    } else {
      LOGGER.debug("[{}] Tokens are still valid", name);
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
        used.thenRun(() -> LOGGER.warn(message, args));
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

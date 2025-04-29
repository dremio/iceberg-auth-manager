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

import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.flow.Flow;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowContext;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowContextFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Token;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.io.Closeable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.rest.RESTClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An OAuth2 agent that supports fetching and refreshing access tokens, as well as impersonation
 * scenarios.
 */
public final class OAuth2Agent implements Closeable {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Agent.class);

  private static final Duration MIN_WARN_INTERVAL = Duration.ofSeconds(10);

  private final OAuth2AgentSpec spec;
  private final ScheduledExecutorService executor;
  private final String name;
  private final Clock clock;

  private final CompletableFuture<Void> used = new CompletableFuture<>();
  private final AtomicBoolean closing = new AtomicBoolean();
  private final AtomicBoolean sleeping = new AtomicBoolean();

  private volatile FlowContext context;
  private volatile FlowContext impersonationContext;

  private volatile CompletionStage<Tokens> currentTokensStage;
  private volatile ScheduledFuture<?> tokenRefreshFuture;
  private volatile Instant lastAccess;
  private volatile Instant lastWarn;

  public OAuth2Agent(
      OAuth2AgentSpec spec, ScheduledExecutorService executor, RESTClient restClient) {
    this.spec = spec;
    this.executor = executor;
    name = spec.getRuntimeConfig().getAgentName();
    clock = spec.getRuntimeConfig().getClock();
    context = FlowContextFactory.createFlowContext(spec, restClient);
    impersonationContext = FlowContextFactory.createImpersonationFlowContext(spec, restClient);
    lastAccess = clock.instant();
    if (spec.getBasicConfig().getToken().isPresent()) {
      currentTokensStage =
          CompletableFuture.completedFuture(Tokens.of(spec.getBasicConfig().getToken().get(), null))
              .thenApplyAsync(this::maybeImpersonate, executor);
    } else {
      // when user interaction is not required, token fetch can happen immediately;
      // otherwise, it will be deferred until authenticate() is called the first time,
      // in order to avoid bothering the user with a login prompt before the agent is actually used.
      CompletableFuture<?> ready =
          spec.getBasicConfig().getGrantType().requiresUserInteraction()
              ? used
              : CompletableFuture.completedFuture(null);
      currentTokensStage =
          ready.thenApplyAsync((v) -> fetchNewTokens(), executor).thenApply(this::maybeImpersonate);
    }
    currentTokensStage
        .whenComplete(this::log)
        .whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
  }

  public void updateRestClient(RESTClient restClient) {
    FlowContext ctx = context;
    FlowContext impersonationCtx = impersonationContext;
    this.context = FlowContextFactory.withRestClient(ctx, restClient);
    this.impersonationContext = FlowContextFactory.withRestClient(impersonationCtx, restClient);
  }

  /** Authenticates the client and returns the current access token. */
  public AccessToken authenticate() {
    return doAuthenticate().getAccessToken();
  }

  Tokens doAuthenticate() {
    if (closing.get()) {
      throw new IllegalStateException("Agent is closing");
    }
    LOGGER.debug("[{}] Authenticating with current token", name);
    used.complete(null);
    maybeWakeUp();
    return getCurrentTokens();
  }

  Tokens getCurrentTokens() {
    try {
      return currentTokensStage.toCompletableFuture().get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
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
      LOGGER.debug("[{}] Closing...", name);
      try {
        currentTokensStage.toCompletableFuture().cancel(true);
        ScheduledFuture<?> tokenRefreshFuture = this.tokenRefreshFuture;
        if (tokenRefreshFuture != null) {
          tokenRefreshFuture.cancel(true);
        }
      } finally {
        // Cancel this future to invalidate any pending log messages
        used.cancel(true);
        tokenRefreshFuture = null;
      }
      LOGGER.debug("[{}] Closed", name);
    }
  }

  Tokens fetchNewTokens() {
    LOGGER.debug(
        "[{}] Fetching new access token using {}", name, spec.getBasicConfig().getGrantType());
    try (Flow flow =
        FlowFactory.forInitialTokenFetch(spec.getBasicConfig().getGrantType(), context)) {
      return flow.fetchNewTokens(getCurrentTokensIfAvailable());
    } finally {
      if (spec.getBasicConfig().getGrantType().requiresUserInteraction()) {
        lastAccess = clock.instant();
      }
    }
  }

  Tokens refreshCurrentTokens(Tokens currentTokens) {
    if (spec.getBasicConfig().getDialect() == Dialect.STANDARD) {
      RefreshToken refreshToken = currentTokens.getRefreshToken();
      Instant nowWithSafety = clock.instant().plus(spec.getTokenRefreshConfig().getSafetyWindow());
      if (refreshToken == null || refreshToken.isExpired(nowWithSafety)) {
        LOGGER.debug("[{}] Must fetch new tokens", name);
        throw new MustFetchNewTokensException();
      }
    }
    LOGGER.debug("[{}] Refreshing tokens", name);
    try (Flow flow = FlowFactory.forTokenRefresh(spec.getBasicConfig().getDialect(), context)) {
      return flow.fetchNewTokens(currentTokens);
    }
  }

  Tokens maybeImpersonate(Tokens currentTokens) {
    if (spec.getImpersonationConfig().isEnabled()) {
      LOGGER.debug("[{}] Performing impersonation", name);
      try (Flow flow = FlowFactory.forImpersonation(impersonationContext)) {
        return flow.fetchNewTokens(currentTokens);
      }
    }
    return currentTokens;
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
      maybeWarn("Failed to fetch new tokens", error);
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
    boolean idle =
        Duration.between(lastAccess, now).compareTo(spec.getTokenRefreshConfig().getIdleTimeout())
            > 0;
    if (idle) {
      maybeSleep(false);
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
      tokenRefreshFuture =
          executor.schedule(this::renewTokens, delay.toMillis(), TimeUnit.MILLISECONDS);
      if (closing.get()) {
        // We raced with close() but the executor wasn't closed yet,
        // so the task was accepted: cancel the future now.
        tokenRefreshFuture.cancel(true);
      }
    } catch (RejectedExecutionException e) {
      if (closing.get()) {
        // We raced with close(), ignore
        return;
      }
      maybeSleep(true);
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
          "Access token has no expiration time, assuming lifespan of " + defaultLifespan, null);
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

  private void renewTokens() {
    CompletionStage<Tokens> oldTokensStage = currentTokensStage;
    CompletionStage<Tokens> newTokensStage =
        oldTokensStage
            // try refreshing the current access token, if any
            .thenApply(this::refreshCurrentTokens)
            // if that fails, try fetching brand-new tokens
            .exceptionally(error -> fetchNewTokens())
            .thenApply(this::maybeImpersonate);
    currentTokensStage = newTokensStage;
    newTokensStage
        .whenComplete(this::log)
        .whenComplete((tokens, error) -> maybeScheduleTokensRenewal(tokens));
  }

  private void maybeSleep(boolean onFailedRenewalSchedule) {
    if (!spec.getTokenRefreshConfig().isEnabled()) {
      LOGGER.debug(
          "[{}] Agent is not configured to keep tokens refreshed, not entering sleep", name);
      return;
    }
    if (onFailedRenewalSchedule) {
      maybeWarn("Failed to schedule next token renewal, forcibly sleeping", null);
    }
    sleeping.set(true);
    LOGGER.debug("[{}] Sleeping...", name);
  }

  private void maybeWakeUp() {
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
    Tokens currentTokens = getCurrentTokensIfAvailable();
    Duration delay = nextTokenRefresh(currentTokens, now, Duration.ZERO);
    if (delay.compareTo(spec.getTokenRefreshConfig().getMinRefreshDelay()) < 0) {
      LOGGER.debug("[{}] Refreshing tokens immediately", name);
      renewTokens();
    } else {
      LOGGER.debug("[{}] Tokens are still valid", name);
      scheduleTokensRenewal(delay);
    }
  }

  private Tokens getCurrentTokensIfAvailable() {
    try {
      CompletionStage<Tokens> tokensStage = currentTokensStage;
      if (tokensStage != null) {
        return tokensStage.toCompletableFuture().getNow(null);
      }
    } catch (CancellationException | CompletionException ignored) {
    }
    return null;
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  private void maybeWarn(String message, Throwable error) {
    Instant now = clock.instant();
    Instant last = lastWarn;
    boolean shouldWarn =
        last == null || Duration.between(last, now).compareTo(MIN_WARN_INTERVAL) > 0;
    if (shouldWarn) {
      // defer logging until the agent is used to avoid confusing log messages appearing
      // before the agent is actually used
      if (error instanceof RESTException) {
        used.thenRun(() -> LOGGER.warn(message, name, error.toString()));
      } else {
        used.thenRun(() -> LOGGER.warn(message, name, error));
      }
      lastWarn = now;
    } else if (LOGGER.isDebugEnabled()) {
      String debugMsg = "[{}] " + message;
      LOGGER.debug(debugMsg, name, error);
    }
  }

  static class MustFetchNewTokensException extends RuntimeException {}
}

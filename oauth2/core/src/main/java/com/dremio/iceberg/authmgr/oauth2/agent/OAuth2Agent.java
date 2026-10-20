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
import com.dremio.iceberg.authmgr.oauth2.dpop.DpopContext;
import com.dremio.iceberg.authmgr.oauth2.dpop.DpopScope;
import com.dremio.iceberg.authmgr.oauth2.flow.Flow;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowFactory;
import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import jakarta.annotation.Nullable;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
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
import java.util.function.BiConsumer;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** An OAuth2 agent that supports fetching and refreshing access tokens. */
public final class OAuth2Agent implements Closeable {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Agent.class);

  private static final Duration MIN_WARN_INTERVAL = Duration.ofSeconds(10);

  /**
   * The longest delay between two renewal attempts when renewals keep failing: the backoff starts
   * at the minimum refresh delay and doubles with every consecutive failure up to this value.
   */
  static final Duration MAX_BACKOFF = Duration.ofMinutes(1);

  /**
   * The longest a server-requested {@code Retry-After} delay can push back a renewal. Rate-limiting
   * servers ask for seconds or minutes; anything longer is treated as this value, so that a bogus
   * or hostile header cannot park the agent for hours.
   */
  static final Duration MAX_RETRY_AFTER = Duration.ofMinutes(5);

  private static final CompletableFuture<TokensResult> MUST_FETCH_NEW_TOKENS_FUTURE =
      CompletableFuture.failedFuture(MustFetchNewTokensException.INSTANCE);

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

  /**
   * The number of renewals that failed in a row, reset by the first successful one. Drives the
   * exponential backoff between renewal attempts, see {@link #nextTokenRefresh(TokensResult,
   * Instant, Throwable, int)}.
   *
   * <p>Only written by {@link #maybeScheduleTokensRenewal}, once a renewal (or the initial fetch)
   * has completed. Renewals never overlap, as each one is scheduled by the completion of the
   * previous one, so its read-modify-write is safe without locking.
   */
  private volatile int consecutiveFailures;

  /**
   * How many times in a row the refresh of the current tokens failed with a transient error and was
   * left to a later renewal, instead of falling back to the initial grant; see {@link
   * #handleRefreshResult}. Reset when a refresh succeeds, and when the agent falls back to the
   * initial grant.
   *
   * <p>Not to be confused with {@link #consecutiveFailures}, which counts failed renewals of any
   * kind to space out renewal attempts, and is only reset by a successful renewal. This counter is
   * the retry budget of a refresh token instead: resetting it on fallback means that during a long
   * outage, the agent falls back to the initial grant only once every {@code max-retries + 1}
   * renewals, rather than on every renewal once the budget is exhausted.
   *
   * <p>Only written by {@link #handleRefreshResult}, in the renewal chain; renewals never overlap,
   * so its read-modify-write is safe without locking.
   */
  private volatile int refreshRetries;

  public OAuth2Agent(OAuth2Config config, OAuth2AgentRuntime runtime) {
    this.config = config;
    this.executor = runtime.getExecutor();
    this.flowFactory = FlowFactory.create(config, runtime);
    name = config.getSystemConfig().getAgentName();
    clock = runtime.getClock();
    lastAccess = clock.instant();
    config
        .getBasicConfig()
        .getToken()
        .ifPresentOrElse(this::initWithStaticToken, this::initWithDynamicToken);
  }

  /**
   * Initializes the agent with a static initial access token. In this situation, a static access
   * token has been provided in the configuration, and it will be used as-is as the first initial
   * token.
   */
  private void initWithStaticToken(AccessToken token) {
    TokensResult currentTokens = TokensResult.of(token);
    currentTokensFuture = CompletableFuture.completedFuture(currentTokens);
    maybeScheduleTokensRenewal(currentTokens, null);
  }

  /**
   * Initializes the agent with a dynamically-obtained initial access token.
   *
   * <p>This method triggers the initial token fetch operation, either immediately, or in a deferred
   * fashion: when user interaction is not required, the initial token fetch can happen immediately;
   * otherwise, it will be deferred until {@link #authenticate()} is called the first time, in order
   * to avoid bothering the user with a login prompt before the agent is actually used.
   */
  @SuppressWarnings("FutureReturnValueIgnored")
  private void initWithDynamicToken() {
    boolean requiresUserInteraction =
        ConfigUtils.requiresUserInteraction(config.getBasicConfig().getGrantType());
    CompletableFuture<?> agentReady =
        requiresUserInteraction ? agentAccessed : CompletableFuture.completedFuture(null);
    currentTokensFuture =
        agentReady
            .thenComposeAsync(v -> fetchNewTokens(), executor)
            .whenComplete(this::log)
            .whenComplete(this::maybeScheduleTokensRenewal);
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
    currentTokensFuture.whenComplete(this::maybeScheduleTokensRenewal);
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
   * Emits the authentication headers that should be applied to an outgoing request.
   *
   * <p>At minimum, this emits an {@code Authorization} header whose scheme matches the current
   * access token's type (e.g. {@code Bearer} for standard tokens, {@code DPoP} for DPoP-bound
   * tokens). When DPoP is enabled and the token is DPoP-bound, an additional {@code DPoP} header
   * carries a fresh proof JWT bound to {@code httpMethod}, {@code requestUri}, and the access
   * token.
   *
   * @param httpMethod the HTTP method of the outgoing request (e.g. {@code GET}, {@code POST}).
   * @param requestUri the full URI of the outgoing request (used to populate the DPoP proof's
   *     {@code htu} claim when applicable).
   * @param headerConsumer the callback invoked once per header to apply.
   */
  public void applyAuthentication(
      String httpMethod, URI requestUri, BiConsumer<String, String> headerConsumer) {
    AccessToken token = authenticate();
    headerConsumer.accept("Authorization", token.toAuthorizationHeader());
    DpopContext dpop = flowFactory.getDpopContext();
    if (dpop != null && token instanceof DPoPAccessToken) {
      SignedJWT proof =
          dpop.createProof(DpopScope.RS, httpMethod, requestUri, (DPoPAccessToken) token);
      headerConsumer.accept("DPoP", proof.serialize());
    }
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
      // This wait is guaranteed to never block indefinitely,
      // because the current tokens future always completes eventually
      // (either with tokens or with an error – including timeouts).
      return currentTokensFuture.get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof TimeoutException) {
        throw new RuntimeException("Token acquisition timed out", cause);
      } else if (cause instanceof Error) {
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
    Duration timeout = config.getBasicConfig().getTimeout();
    CompletableFuture<TokensResult> newTokensFuture =
        flow.fetchNewTokens()
            .toCompletableFuture()
            .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS);
    // If the flow requires user interaction, update the last access time once the flow completes,
    // in order to better reflect when the agent was actually accessed for the last time.
    // This prevents the agent from going to sleep too early when the user is interacting with it.
    return ConfigUtils.requiresUserInteraction(config.getBasicConfig().getGrantType())
        ? newTokensFuture.whenComplete((tokens, error) -> lastAccess = clock.instant())
        : newTokensFuture;
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
    Duration timeout = config.getBasicConfig().getTimeout();
    return flow.fetchNewTokens()
        .toCompletableFuture()
        .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS);
  }

  private void log(@Nullable TokensResult newTokens, @Nullable Throwable error) {
    if (!closing.get()) {
      if (newTokens != null) {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(
              "[{}] Successfully renewed tokens. Access token expiration time: {}",
              name,
              newTokens.getAccessTokenExpirationTime());
        }
      } else if (error != null) {
        Throwable cause = error instanceof CompletionException ? error.getCause() : error;
        if (cause instanceof OAuth2Exception) {
          // Don't include the stack trace if the error is an OAuth2Exception,
          // since it's not very useful and just clutters the logs.
          maybeWarn("[{}] Failed to renew tokens: {}", name, cause.toString());
        } else {
          maybeWarn("[{}] Failed to renew tokens", name, cause);
        }
      }
    }
  }

  /**
   * Schedules the next token renewal, unless the agent is idle, in which case it goes to sleep.
   *
   * @param currentTokens the current tokens, if any
   * @param renewalError the error the previous renewal (or the initial fetch) failed with, or null
   *     if it succeeded
   */
  private void maybeScheduleTokensRenewal(
      @Nullable TokensResult currentTokens, @Nullable Throwable renewalError) {
    if (!config.getTokenRefreshConfig().isEnabled()) {
      LOGGER.debug(
          "[{}] Agent is not configured to keep tokens refreshed, skipping token renewal", name);
      return;
    }
    if (closing.get()) {
      LOGGER.debug("[{}] Not checking if token renewal is required, agent is closing", name);
      return;
    }
    int failures = renewalError == null ? 0 : consecutiveFailures + 1;
    consecutiveFailures = failures;
    Instant now = clock.instant();
    Duration timeSinceLastAccess = Duration.between(lastAccess, now);
    boolean idle =
        timeSinceLastAccess.compareTo(config.getTokenRefreshConfig().getIdleTimeout()) > 0;
    LOGGER.debug("[{}] Time since last access: {}, idle: {}", name, timeSinceLastAccess, idle);
    if (idle) {
      maybeSleep();
    } else {
      Duration delay = nextTokenRefresh(currentTokens, now, renewalError, failures);
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

  /**
   * Same as {@link #nextTokenRefresh(TokensResult, Instant)}, but for the renewal following a
   * failed one. The delay is never shorter than:
   *
   * <ul>
   *   <li>an exponential backoff: the minimum refresh delay doubled for each consecutive failure
   *       beyond the first, capped at {@link #MAX_BACKOFF}. A transient failure is thus retried
   *       quickly, while a persistent one settles at one attempt per {@link #MAX_BACKOFF};
   *   <li>the {@code Retry-After} delay the server sent along with the error, if any, capped at
   *       {@link #MAX_RETRY_AFTER}. This is how the agent backs off when it is rate-limited: the
   *       HTTP client never waits inline.
   * </ul>
   *
   * @param renewalError the error the previous renewal failed with, or null if it succeeded
   * @param consecutiveFailures how many renewals failed in a row, including the last one; 0 if it
   *     succeeded
   */
  private Duration nextTokenRefresh(
      @Nullable TokensResult currentTokens,
      Instant now,
      @Nullable Throwable renewalError,
      int consecutiveFailures) {
    Duration delay = nextTokenRefresh(currentTokens, now);
    if (renewalError != null) {
      if (consecutiveFailures > 0) {
        Duration backoff = backoff(consecutiveFailures);
        if (backoff.compareTo(delay) > 0) {
          LOGGER.debug(
              "[{}] {} consecutive renewal failure(s), backing off for {}",
              name,
              consecutiveFailures,
              backoff);
          delay = backoff;
        }
      }
      Duration retryAfter = retryAfter(renewalError);
      if (retryAfter != null && retryAfter.compareTo(delay) > 0) {
        if (currentTokens != null
            && !currentTokens.isAccessTokenExpired(now)
            && currentTokens.isAccessTokenExpired(now.plus(retryAfter))) {
          maybeWarn(
              "[{}] Server asked to retry after {}, but the access token expires at {}: "
                  + "it will expire before it can be renewed",
              name,
              retryAfter,
              currentTokens.getAccessTokenExpirationTime());
        } else {
          LOGGER.debug(
              "[{}] Server asked to retry after {}, delaying next renewal accordingly",
              name,
              retryAfter);
        }
        delay = retryAfter;
      }
    }
    return delay;
  }

  /** The backoff delay for the given number of consecutive failures (at least 1). */
  private Duration backoff(int consecutiveFailures) {
    Duration minRefreshDelay = config.getTokenRefreshConfig().getMinRefreshDelay();
    // 2^(n-1) times the minimum delay; the exponent is capped at 30 for security.
    // In practice any exponent > 5 reaches MAX_BACKOFF.
    Duration backoff = minRefreshDelay.multipliedBy(1L << Math.min(consecutiveFailures - 1, 30));
    return backoff.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : backoff;
  }

  /** The capped {@code Retry-After} delay carried by the given error, or null if none. */
  @Nullable
  private static Duration retryAfter(Throwable error) {
    Throwable cause =
        error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
    if (cause instanceof OAuth2Exception oae) {
      Duration retryAfter = oae.getRetryAfter().orElse(null);
      if (retryAfter != null && retryAfter.compareTo(MAX_RETRY_AFTER) > 0) {
        return MAX_RETRY_AFTER;
      }
      return retryAfter;
    }
    return null;
  }

  /**
   * Whether the given error is likely to go away on its own: a timeout, an I/O error (e.g. a
   * connection refused or reset, or a read timeout), or a server error (HTTP 5xx). Errors returned
   * by the server with a 4xx status, e.g. {@code invalid_grant}, are not transient.
   */
  static boolean isTransientError(Throwable error) {
    for (Throwable t = error; t != null; t = t.getCause()) {
      if (t instanceof OAuth2Exception oae) {
        return oae.getHttpStatusCode() >= 500;
      }
      if (t instanceof TimeoutException || t instanceof IOException) {
        return true;
      }
    }
    return false;
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  private void renewTokens() {
    if (closing.get()) {
      LOGGER.debug("[{}] Not renewing tokens, agent is closing", name);
      return;
    }
    CompletableFuture<TokensResult> oldTokensFuture = currentTokensFuture;
    TokensResult oldTokens = Futures.getNow(oldTokensFuture);
    CompletableFuture<TokensResult> renewalFuture =
        oldTokensFuture
            // 1) try refreshing the current access token, if any, and if possible. If the previous
            // renewal failed, there is nothing to refresh: new tokens must be fetched. Replacing
            // that error here guarantees that any other error reaching step 2 comes from the
            // refresh attempt itself.
            .exceptionallyCompose(error -> MUST_FETCH_NEW_TOKENS_FUTURE)
            .thenCompose(this::refreshCurrentTokens)
            // 2) if that fails, try fetching brand-new tokens using the configured initial grant,
            // unless the refresh failed with an error worth retrying later
            .handle(this::handleRefreshResult)
            .thenCompose(Function.identity())
            // 3) log the result of the token renewal attempt
            .whenComplete(this::log);
    CompletableFuture<TokensResult> newTokensFuture =
        renewalFuture
            // 4) if the renewal attempt failed, keep the old tokens if available
            .handle((newTokens, error) -> handleRenewalResult(oldTokens, newTokens, error))
            .thenCompose(Function.identity());
    currentTokensFuture = newTokensFuture;
    if (closing.get()) {
      // We raced with close(): cancel the future we just created.
      Futures.cancel(newTokensFuture);
    } else {
      // 5) schedule the next token renewal; if the renewal attempt failed, back off, even if the
      // old tokens were kept
      newTokensFuture.whenComplete(
          (tokens, error) ->
              maybeScheduleTokensRenewal(tokens, Futures.getErrorNow(renewalFuture)));
    }
  }

  /**
   * Handles the result of a token refresh attempt. If the refresh wasn't successful, or if the
   * refreshed access token lifespan is too short, the refreshed token is discarded and a new token
   * is fetched.
   *
   * <p>If the refresh was rate-limited, or failed with a transient error and the retry budget is
   * not exhausted yet, no new tokens are fetched: the renewal fails, the current tokens are kept,
   * and the next renewal, scheduled with a backoff, tries refreshing them again.
   */
  private CompletionStage<TokensResult> handleRefreshResult(
      @Nullable TokensResult newTokens, @Nullable Throwable error) {
    if (newTokens != null) {
      refreshRetries = 0;
      Instant now = clock.instant();
      Instant expirationTime = expirationTime(newTokens);
      Duration safetyWindow = config.getTokenRefreshConfig().getSafetyWindow();
      if (expirationTime.minus(safetyWindow).isAfter(now)) {
        return CompletableFuture.completedFuture(newTokens);
      } else {
        LOGGER.debug("[{}] Refreshed access token is too short: fetching new tokens instead", name);
      }
    } else if (error != null) {
      Throwable cause = error instanceof CompletionException ? error.getCause() : error;
      if (cause instanceof OAuth2Exception oae && oae.isRateLimited()) {
        // The token endpoint is throttling us: fetching new tokens would hit it again right away,
        // and for interactive grants would needlessly prompt the user although the refresh token
        // is most likely still valid. Fail this renewal; the next one honors Retry-After.
        LOGGER.debug("[{}] Refresh was rate-limited, not fetching new tokens", name);
        return CompletableFuture.failedFuture(cause);
      }
      int retries = refreshRetries;
      if (retries < config.getTokenRefreshConfig().getMaxRetries() && isTransientError(cause)) {
        // Same reasoning as above: the token endpoint is likely unavailable, and the initial grant
        // may not be usable anymore. Fail this renewal; the next one retries the refresh with a
        // backoff, even if the access token has expired by then.
        refreshRetries = retries + 1;
        LOGGER.debug(
            "[{}] Refresh failed with a transient error, will retry (retry {}): {}",
            name,
            retries + 1,
            cause.toString());
        return CompletableFuture.failedFuture(cause);
      }
      if (!(cause instanceof MustFetchNewTokensException)) {
        LOGGER.debug("[{}] Refresh failed unexpectedly, fetching new tokens instead", name, error);
      }
      // Giving up on this refresh: the next one, if any, starts with a fresh retry budget.
      refreshRetries = 0;
    }
    return fetchNewTokens();
  }

  /**
   * Handles the result of a token renewal attempt. If the renewal wasn't successful, the old tokens
   * are kept if available; otherwise, the error is propagated.
   */
  private CompletionStage<TokensResult> handleRenewalResult(
      @Nullable TokensResult oldTokens,
      @Nullable TokensResult newTokens,
      @Nullable Throwable error) {
    return error == null
        ? CompletableFuture.completedFuture(newTokens)
        : oldTokens != null
            ? CompletableFuture.completedFuture(oldTokens)
            : CompletableFuture.failedFuture(error);
  }

  /**
   * Returns the access token expiration time, based on {@link
   * TokensResult#getAccessTokenExpirationTime()} if available, or by adding the default access
   * token lifespan to the current time otherwise.
   */
  private Instant expirationTime(TokensResult currentTokens) {
    Instant exp = currentTokens.getAccessTokenExpirationTime();
    return exp != null
        ? exp
        : clock.instant().plus(config.getTokenRefreshConfig().getAccessTokenLifespan());
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

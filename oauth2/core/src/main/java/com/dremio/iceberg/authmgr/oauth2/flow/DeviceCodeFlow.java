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
package com.dremio.iceberg.authmgr.oauth2.flow;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationResponse;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.io.PrintStream;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
 * Authorization Grant</a> flow.
 */
@AuthManagerImmutable
abstract class DeviceCodeFlow extends AbstractFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeviceCodeFlow.class);

  interface Builder extends AbstractFlow.Builder<DeviceCodeFlow, Builder> {}

  @Override
  public final GrantType getGrantType() {
    return GrantType.DEVICE_CODE;
  }

  @Value.Derived
  String getAgentName() {
    return getConfig().getSystemConfig().getAgentName();
  }

  @Value.Derived
  String getMsgPrefix() {
    return AbstractFlow.getMsgPrefix(getAgentName());
  }

  /**
   * A future that will complete when fresh tokens are eventually obtained after polling the token
   * endpoint.
   */
  @Value.Default
  CompletableFuture<TokensResult> getTokensFuture() {
    return new CompletableFuture<>();
  }

  @Value.Default
  TokenPoller getPoller() {
    return new TokenPoller();
  }

  @Override
  @SuppressWarnings("FutureReturnValueIgnored")
  public CompletionStage<TokensResult> fetchNewTokens() {
    LOGGER.debug("[{}] Device Auth Flow: started", getAgentName());
    // Return getTokensFuture() directly so that cancelling the result of fetchNewTokens()
    // will complete getTokensFuture() itself, which triggers stopPolling().
    // The device authorization endpoint call is a side effect:
    // on success it starts polling, on failure it completes getTokensFuture() exceptionally.
    invokeDeviceAuthorizationEndpoint()
        .thenAccept(
            response -> {
              PrintStream console = getRuntime().getConsole();
              synchronized (console) {
                console.println();
                console.println(getMsgPrefix() + OAUTH2_AGENT_TITLE);
                console.println(getMsgPrefix() + OAUTH2_AGENT_OPEN_URL);
                console.println(getMsgPrefix() + response.getVerificationURI());
                console.println(getMsgPrefix() + "And enter the code:");
                console.println(getMsgPrefix() + response.getUserCode().getValue());
                printExpirationNotice(response.getLifetime());
                console.println();
                console.flush();
              }
              getPoller().start(response.getInterval(), response.getDeviceCode());
            })
        .exceptionally(
            error -> {
              getTokensFuture()
                  .completeExceptionally(
                      error instanceof CompletionException && error.getCause() != null
                          ? error.getCause()
                          : error);
              return null;
            });
    getTokensFuture().whenComplete((result, error) -> getPoller().stop());
    return getTokensFuture();
  }

  private CompletionStage<DeviceAuthorizationSuccessResponse> invokeDeviceAuthorizationEndpoint() {
    DeviceAuthorizationRequest.Builder builder =
        isPublicClient()
            ? new DeviceAuthorizationRequest.Builder(
                getConfig().getBasicConfig().getClientId().orElseThrow())
            : new DeviceAuthorizationRequest.Builder(createClientAuthentication());
    builder.endpointURI(getEndpointProvider().getResolvedDeviceAuthorizationEndpoint());
    getConfig().getBasicConfig().getScope().ifPresent(builder::scope);
    getConfig().getBasicConfig().getExtraRequestParameters().forEach(builder::customParameter);
    HTTPRequest request = builder.build().toHTTPRequest();
    return CompletableFuture.supplyAsync(() -> sendAndReceive(request), getRuntime().getExecutor())
        .whenComplete((response, error) -> log(request, response, error))
        .thenApply(this::parseDeviceAuthorizationResponse);
  }

  private DeviceAuthorizationSuccessResponse parseDeviceAuthorizationResponse(
      HTTPResponse httpResponse) {
    try {
      DeviceAuthorizationResponse response = DeviceAuthorizationResponse.parse(httpResponse);
      if (!response.indicatesSuccess()) {
        DeviceAuthorizationErrorResponse errorResponse = response.toErrorResponse();
        throw new OAuth2Exception(errorResponse);
      }
      return response.toSuccessResponse();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private void printExpirationNotice(long seconds) {
    String exp;
    if (seconds < 60) {
      exp = seconds + " seconds";
    } else if (seconds % 60 == 0) {
      exp = seconds / 60 + " minutes";
    } else {
      exp = seconds / 60 + " minutes and " + seconds % 60 + " seconds";
    }
    PrintStream console = getRuntime().getConsole();
    console.println(getMsgPrefix() + "(The code will expire in " + exp + ")");
  }

  /** Encapsulates mutable state and behavior related to token endpoint polling. */
  class TokenPoller {

    private final ScheduledExecutorService executor = getRuntime().getExecutor();
    private final AtomicBoolean stopped = new AtomicBoolean(false);

    private volatile Duration pollInterval;
    private volatile Future<?> pollFuture;

    void start(long serverPollInterval, DeviceCode deviceCode) {
      pollInterval = getConfig().getDeviceCodeConfig().getPollInterval();
      boolean ignoreServerPollInterval =
          getConfig().getDeviceCodeConfig().ignoreServerPollInterval();
      if (!ignoreServerPollInterval && serverPollInterval > pollInterval.getSeconds()) {
        LOGGER.debug(
            "[{}] Device Auth Flow: server requested minimum poll interval of {} seconds",
            getAgentName(),
            serverPollInterval);
        pollInterval = Duration.ofSeconds(serverPollInterval);
      }
      scheduleNextPoll(deviceCode);
    }

    void stop() {
      if (stopped.compareAndSet(false, true)) {
        LOGGER.debug("[{}] Device Auth Flow: stopping polling", getAgentName());
        try {
          Future<?> future = this.pollFuture;
          if (future != null) {
            future.cancel(true);
          }
        } finally {
          this.pollFuture = null;
        }
      }
    }

    private void poll(DeviceCode deviceCode) {
      LOGGER.debug("[{}] Device Auth Flow: polling for new tokens", getAgentName());
      invokeTokenEndpoint(new DeviceCodeGrant(deviceCode))
          .whenComplete(
              (tokens, error) -> {
                if (error == null) {
                  LOGGER.debug("[{}] Device Auth Flow: new tokens received", getAgentName());
                  getTokensFuture().complete(tokens);
                } else {
                  Throwable cause = error;
                  if (cause instanceof CompletionException) {
                    cause = error.getCause();
                  }
                  if (cause instanceof OAuth2Exception) {
                    switch (((OAuth2Exception) cause).getErrorObject().getCode()) {
                      case "authorization_pending":
                        LOGGER.debug(
                            "[{}] Device Auth Flow: waiting for authorization to complete",
                            getAgentName());
                        scheduleNextPoll(deviceCode);
                        break;
                      case "slow_down":
                        LOGGER.debug(
                            "[{}] Device Auth Flow: server requested to slow down", getAgentName());
                        boolean ignoreServerPollInterval =
                            getConfig().getDeviceCodeConfig().ignoreServerPollInterval();
                        if (!ignoreServerPollInterval) {
                          Duration interval = pollInterval;
                          pollInterval = interval.plus(interval);
                        }
                        scheduleNextPoll(deviceCode);
                        break;
                      default:
                        getTokensFuture().completeExceptionally(cause);
                    }
                  } else {
                    getTokensFuture().completeExceptionally(cause);
                  }
                }
              });
    }

    private void scheduleNextPoll(DeviceCode deviceCode) {
      if (!stopped.get()) {
        Future<?> future =
            executor.schedule(
                () -> poll(deviceCode), pollInterval.toMillis(), TimeUnit.MILLISECONDS);
        pollFuture = future;
        if (stopped.get()) {
          // We raced with stop(): clear the field and cancel the future we just created.
          pollFuture = null;
          future.cancel(true);
        }
      }
    }
  }
}

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

import static com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils.OAUTH2_AGENT_OPEN_URL;
import static com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils.OAUTH2_AGENT_TITLE;

import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAccessTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.io.PrintStream;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
 * Authorization Grant</a> flow.
 */
@AuthManagerImmutable
abstract class DeviceCodeFlow extends AbstractFlow implements InitialFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeviceCodeFlow.class);

  interface Builder extends AbstractFlow.Builder<DeviceCodeFlow, Builder> {}

  @Value.Derived
  String getAgentName() {
    return getSpec().getRuntimeConfig().getAgentName();
  }

  @Value.Derived
  String getMsgPrefix() {
    return FlowUtils.getMsgPrefix(getSpec().getRuntimeConfig().getAgentName());
  }

  /**
   * A future that will complete when fresh tokens are eventually obtained after polling the token
   * endpoint.
   */
  @Value.Default
  @SuppressWarnings("FutureReturnValueIgnored")
  CompletableFuture<Tokens> getTokensFuture() {
    CompletableFuture<Tokens> future = new CompletableFuture<>();
    future.whenComplete((tokens, error) -> stopPolling());
    return future;
  }

  @SuppressWarnings("immutables:incompat")
  private volatile Duration pollInterval;

  @SuppressWarnings("immutables:incompat")
  private volatile Future<?> pollFuture;

  private void stopPolling() {
    LOGGER.debug("[{}] Device Auth Flow: closing", getAgentName());
    Future<?> pollFuture = this.pollFuture;
    if (pollFuture != null) {
      pollFuture.cancel(true);
    }
    this.pollFuture = null;
  }

  @Override
  public CompletionStage<Tokens> fetchNewTokens() {
    LOGGER.debug("[{}] Device Auth Flow: started", getAgentName());
    return invokeDeviceAuthEndpoint()
        .thenCompose(
            response -> {
              pollInterval = getSpec().getDeviceCodeConfig().getPollInterval();
              checkPollInterval(response.getIntervalSeconds());
              PrintStream console = getSpec().getRuntimeConfig().getConsole();
              synchronized (console) {
                console.println();
                console.println(getMsgPrefix() + OAUTH2_AGENT_TITLE);
                console.println(getMsgPrefix() + OAUTH2_AGENT_OPEN_URL);
                console.println(getMsgPrefix() + response.getVerificationUri());
                console.println(getMsgPrefix() + "And enter the code:");
                console.println(getMsgPrefix() + response.getUserCode());
                printExpirationNotice(response.getExpiresInSeconds());
                console.println();
                console.flush();
              }
              pollFuture = getExecutor().submit(() -> pollForNewTokens(response.getDeviceCode()));
              return getTokensFuture();
            });
  }

  private void checkPollInterval(Integer serverPollInterval) {
    boolean ignoreServerPollInterval = getSpec().getDeviceCodeConfig().ignoreServerPollInterval();
    if (!ignoreServerPollInterval
        && serverPollInterval != null
        && serverPollInterval > pollInterval.getSeconds()) {
      LOGGER.debug(
          "[{}] Device Auth Flow: server requested minimum poll interval of {} seconds",
          getAgentName(),
          serverPollInterval);
      pollInterval = Duration.ofSeconds(serverPollInterval);
    }
  }

  private void printExpirationNotice(int seconds) {
    String exp;
    if (seconds < 60) {
      exp = seconds + " seconds";
    } else if (seconds % 60 == 0) {
      exp = seconds / 60 + " minutes";
    } else {
      exp = seconds / 60 + " minutes and " + seconds % 60 + " seconds";
    }
    PrintStream console = getSpec().getRuntimeConfig().getConsole();
    console.println(getMsgPrefix() + "(The code will expire in " + exp + ")");
  }

  private void pollForNewTokens(String deviceCode) {
    LOGGER.debug("[{}] Device Auth Flow: polling for new tokens", getAgentName());
    DeviceAccessTokenRequest.Builder request =
        DeviceAccessTokenRequest.builder().deviceCode(deviceCode);
    invokeTokenEndpoint(null, request)
        .whenComplete(
            (tokens, error) -> {
              if (error == null) {
                LOGGER.debug("[{}] Device Auth Flow: new tokens received", getAgentName());
                getTokensFuture().complete(tokens);
              } else {
                if (error instanceof CompletionException) {
                  error = error.getCause();
                }
                if (error instanceof OAuth2Exception) {
                  switch (((OAuth2Exception) error).getErrorResponse().type()) {
                    case "authorization_pending":
                      LOGGER.debug(
                          "[{}] Device Auth Flow: waiting for authorization to complete",
                          getAgentName());
                      pollFuture =
                          getExecutor()
                              .schedule(
                                  () -> pollForNewTokens(deviceCode),
                                  pollInterval.toMillis(),
                                  TimeUnit.MILLISECONDS);
                      return;
                    case "slow_down":
                      LOGGER.debug(
                          "[{}] Device Auth Flow: server requested to slow down", getAgentName());
                      Duration pollInterval = this.pollInterval;
                      boolean ignoreServerPollInterval =
                          getSpec().getDeviceCodeConfig().ignoreServerPollInterval();
                      if (!ignoreServerPollInterval) {
                        pollInterval = pollInterval.plus(pollInterval);
                        this.pollInterval = pollInterval;
                      }
                      pollFuture =
                          getExecutor()
                              .schedule(
                                  () -> pollForNewTokens(deviceCode),
                                  pollInterval.toMillis(),
                                  TimeUnit.MILLISECONDS);
                      return;
                    case "access_denied":
                    case "expired_token":
                    default:
                      getTokensFuture().completeExceptionally(error);
                  }
                } else {
                  getTokensFuture().completeExceptionally(error);
                }
              }
            });
  }
}

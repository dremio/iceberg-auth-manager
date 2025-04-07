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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAccessTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.DeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.io.PrintStream;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.rest.RESTClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
 * Authorization Grant</a> flow.
 */
class DeviceCodeFlow extends AbstractFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeviceCodeFlow.class);

  private final PrintStream console;
  private final String msgPrefix;
  private final Duration flowTimeout;
  private final boolean ignoreServerPollInterval;

  /**
   * A future that will complete when fresh tokens are eventually obtained after polling the token
   * endpoint.
   */
  private final CompletableFuture<Tokens> tokensFuture = new CompletableFuture<>();

  /**
   * A future that will complete when the close() method is called. It is used merely to avoid
   * closing resources multiple times. Its completion stops the internal polling loop and its
   * executor.
   */
  private final CompletableFuture<Void> closeFuture = new CompletableFuture<>();

  /** The executor that is used to periodically poll the token endpoint. */
  private final ScheduledExecutorService executor;

  private volatile Duration pollInterval;
  private volatile Future<?> pollFuture;

  DeviceCodeFlow(OAuth2AgentSpec spec, RESTClient restClient, EndpointResolver endpointResolver) {
    super(spec, restClient, endpointResolver);
    console = spec.getRuntimeConfig().getConsole();
    msgPrefix = FlowUtils.getMsgPrefix(spec.getRuntimeConfig().getAgentName());
    flowTimeout = spec.getDeviceCodeConfig().getTimeout();
    pollInterval = spec.getDeviceCodeConfig().getPollInterval();
    ignoreServerPollInterval = spec.getDeviceCodeConfig().ignoreServerPollInterval();
    closeFuture.thenRun(this::doClose);
    LOGGER.debug("Device Auth Flow: started");
    executor = Executors.newSingleThreadScheduledExecutor();
  }

  @Override
  public void close() {
    closeFuture.complete(null);
  }

  private void doClose() {
    LOGGER.debug("Device Auth Flow: closing");
    executor.shutdownNow();
    pollFuture = null;
    // don't close the HTTP client nor the console, they are not ours
  }

  private void abort() {
    Future<?> pollFuture = this.pollFuture;
    if (pollFuture != null) {
      pollFuture.cancel(true);
    }
    tokensFuture.cancel(true);
  }

  @Override
  public Tokens fetchNewTokens(@Nullable Tokens currentTokens) {
    DeviceAuthorizationResponse response = invokeDeviceAuthEndpoint(currentTokens);
    checkPollInterval(response.getIntervalSeconds());
    console.println();
    console.println(msgPrefix + OAUTH2_AGENT_TITLE);
    console.println(msgPrefix + OAUTH2_AGENT_OPEN_URL);
    console.println(msgPrefix + response.getVerificationUri());
    console.println(msgPrefix + "And enter the code:");
    console.println(msgPrefix + response.getUserCode());
    printExpirationNotice(response.getExpiresInSeconds());
    console.println();
    console.flush();
    pollFuture = executor.submit(() -> pollForNewTokens(response.getDeviceCode()));
    try {
      return tokensFuture.get(flowTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      LOGGER.error("Timed out waiting for user to authorize device.");
      abort();
      throw new RuntimeException("Timed out waiting for user to authorize device", e);
    } catch (InterruptedException e) {
      abort();
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    } catch (ExecutionException e) {
      abort();
      Throwable cause = e.getCause();
      LOGGER.error("Authentication failed: {}", cause.getMessage());
      if (cause instanceof RESTException) {
        throw (RESTException) cause;
      }
      throw new RuntimeException(cause);
    }
  }

  private void checkPollInterval(Integer serverPollInterval) {
    if (!ignoreServerPollInterval
        && serverPollInterval != null
        && serverPollInterval > pollInterval.getSeconds()) {
      LOGGER.debug(
          "Device Auth Flow: server requested minimum poll interval of {} seconds",
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
    console.println(msgPrefix + "(The code will expire in " + exp + ")");
  }

  private void pollForNewTokens(String deviceCode) {
    try {
      LOGGER.debug("Device Auth Flow: polling for new tokens");
      DeviceAccessTokenRequest.Builder request =
          DeviceAccessTokenRequest.builder().deviceCode(deviceCode);
      Tokens tokens = invokeTokenEndpoint(null, request);
      LOGGER.debug("Device Auth Flow: new tokens received");
      tokensFuture.complete(tokens);
    } catch (OAuth2Exception e) {
      switch (e.getErrorResponse().type()) {
        case "authorization_pending":
          LOGGER.debug("Device Auth Flow: waiting for authorization to complete");
          pollFuture =
              executor.schedule(
                  () -> pollForNewTokens(deviceCode),
                  pollInterval.toMillis(),
                  TimeUnit.MILLISECONDS);
          return;
        case "slow_down":
          LOGGER.debug("Device Auth Flow: server requested to slow down");
          Duration pollInterval = this.pollInterval;
          if (!ignoreServerPollInterval) {
            pollInterval = pollInterval.plus(pollInterval);
            this.pollInterval = pollInterval;
          }
          pollFuture =
              executor.schedule(
                  () -> pollForNewTokens(deviceCode),
                  pollInterval.toMillis(),
                  TimeUnit.MILLISECONDS);
          return;
        case "access_denied":
        case "expired_token":
        default:
          tokensFuture.completeExceptionally(e);
      }
    } catch (Exception e) {
      tokensFuture.completeExceptionally(e);
    }
  }
}

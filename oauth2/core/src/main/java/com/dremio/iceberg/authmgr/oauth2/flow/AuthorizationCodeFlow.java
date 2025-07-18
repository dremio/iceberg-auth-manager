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
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.rest.AuthorizationCodeTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import com.dremio.iceberg.authmgr.oauth2.uri.UriUtils;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.FormatMethod;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Phaser;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation of the <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Authorization Code Grant</a>
 * flow.
 */
@AuthManagerImmutable
abstract class AuthorizationCodeFlow extends AbstractFlow implements InitialFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeFlow.class);

  private static final String HTML_TEMPLATE_OK =
      "<html><body><h1>Authentication successful</h1><p>You can close this page now.</p></body></html>";
  private static final String HTML_TEMPLATE_FAILED =
      "<html><body><h1>Authentication failed</h1><p>Could not obtain access token: %s</p></body></html>";

  private static final int STATE_LENGTH = 16;

  interface Builder extends AbstractFlow.Builder<AuthorizationCodeFlow, Builder> {}

  @Value.Derived
  String getAgentName() {
    return getSpec().getRuntimeConfig().getAgentName();
  }

  @Value.Derived
  String getMsgPrefix() {
    return FlowUtils.getMsgPrefix(getSpec().getRuntimeConfig().getAgentName());
  }

  @Value.Derived
  String getState() {
    return FlowUtils.randomAlphaNumString(STATE_LENGTH);
  }

  @Value.Derived
  @Nullable
  String getCodeVerifier() {
    return getSpec().getAuthorizationCodeConfig().isPkceEnabled()
        ? FlowUtils.generateCodeVerifier()
        : null;
  }

  @Value.Derived
  String getBindHost() {
    AuthorizationCodeConfig authorizationCodeConfig = getSpec().getAuthorizationCodeConfig();
    return authorizationCodeConfig.getCallbackBindHost();
  }

  @Value.Derived
  int getBindPort() {
    return getSpec().getAuthorizationCodeConfig().getCallbackBindPort().orElse(0);
  }

  @Value.Derived
  String getContextPath() {
    return getSpec()
        .getAuthorizationCodeConfig()
        .getCallbackContextPath()
        .orElseGet(() -> FlowUtils.getContextPath(getSpec().getRuntimeConfig().getAgentName()));
  }

  @Value.Derived
  HttpServer getServer() {
    return createServer(getBindHost(), getBindPort(), getContextPath(), this::doRequest);
  }

  @Value.Derived
  URI getRedirectUri() {
    return getSpec()
        .getAuthorizationCodeConfig()
        .getRedirectUri()
        .orElseGet(
            () ->
                defaultRedirectUri(
                    getBindHost(), getServer().getAddress().getPort(), getContextPath()));
  }

  @Value.Derived
  URI getAuthorizationUri() {
    UriBuilder authorizationUriBuilder =
        new UriBuilder(getEndpointProvider().getResolvedAuthorizationEndpoint())
            .queryParam("response_type", "code")
            .queryParam("client_id", getSpec().getBasicConfig().getClientId().orElseThrow())
            .queryParam(
                "scope",
                ConfigUtils.scopesAsString(getSpec().getBasicConfig().getScopes()).orElse(null))
            .queryParam("redirect_uri", getRedirectUri().toString())
            .queryParam("state", getState());
    if (getSpec().getAuthorizationCodeConfig().isPkceEnabled()) {
      PkceTransformation transformation =
          getSpec().getAuthorizationCodeConfig().getPkceTransformation();
      String codeChallenge = FlowUtils.generateCodeChallenge(transformation, getCodeVerifier());
      authorizationUriBuilder
          .queryParam("code_challenge", codeChallenge)
          .queryParam("code_challenge_method", transformation.getCanonicalName())
          .build();
    }
    return authorizationUriBuilder.build();
  }

  /**
   * A future that will complete when the redirect URI is called for the first time. It will then
   * trigger the code extraction then the token fetching. Subsequent calls to the redirect URI will
   * not trigger any action. Note that the response to the redirect URI will be delayed until the
   * tokens are received.
   */
  @Value.Default
  CompletableFuture<HttpExchange> getRedirectUriFuture() {
    return new CompletableFuture<>();
  }

  /**
   * A future that will complete when the tokens are received in exchange for the authorization
   * code. Its completion will release all pending responses to the redirect URI. If the redirect
   * URI is called again after the tokens are received, the response will be immediate.
   */
  @Value.Derived
  @SuppressWarnings("FutureReturnValueIgnored")
  CompletableFuture<Tokens> getTokensFuture() {
    CompletableFuture<Tokens> future =
        getRedirectUriFuture()
            .thenApply(this::extractAuthorizationCode)
            .thenCompose(this::fetchNewTokens)
            .whenComplete((tokens, error) -> log(error));
    future.whenCompleteAsync((tokens, error) -> stopServer(), getExecutor());
    return future;
  }

  /**
   * A phaser that will delay closing the internal HTTP server until all inflight requests have been
   * processed. It is used to avoid closing the server prematurely and leaving the user's browser
   * with an aborted HTTP request.
   */
  @Value.Default
  Phaser getInflightRequestsPhaser() {
    return new Phaser(1);
  }

  private void stopServer() {
    // Wait for all in-flight requests to complete before proceeding
    // (note: this call is potentially blocking!)
    getInflightRequestsPhaser().arriveAndAwaitAdvance();
    LOGGER.debug("[{}] Authorization Code Flow: closing", getAgentName());
    getServer().stop(0);
  }

  @Override
  public CompletionStage<Tokens> fetchNewTokens() {
    LOGGER.debug(
        "[{}] Authorization Code Flow: started, redirect URI: {}",
        getAgentName(),
        getRedirectUri());
    PrintStream console = getSpec().getRuntimeConfig().getConsole();
    synchronized (console) {
      console.println();
      console.println(getMsgPrefix() + OAUTH2_AGENT_TITLE);
      console.println(getMsgPrefix() + OAUTH2_AGENT_OPEN_URL);
      console.println(getMsgPrefix() + getAuthorizationUri());
      console.println();
      console.flush();
    }
    return getTokensFuture();
  }

  /**
   * Handle the incoming HTTP request to the redirect URI. Since we are using the default executor,
   * which is a synchronous one, the very first invocation of this method will block the HTTP
   * server's dispatcher thread, until the authorization code is extracted and exchanged for tokens.
   * Subsequent requests will be processed immediately. The response to the request will be delayed
   * until the tokens are received.
   */
  @SuppressWarnings("FutureReturnValueIgnored")
  private void doRequest(HttpExchange exchange) {
    LOGGER.debug("[{}] Authorization Code Flow: received request", getAgentName());
    getInflightRequestsPhaser().register();
    getRedirectUriFuture().complete(exchange); // will trigger the token fetching the first time
    getTokensFuture()
        .handle((tokens, error) -> doResponse(exchange, error))
        .whenComplete((v, error) -> exchange.close())
        .whenComplete((v, error) -> getInflightRequestsPhaser().arriveAndDeregister());
  }

  /** Send the response to the incoming HTTP request to the redirect URI. */
  private Void doResponse(HttpExchange exchange, Throwable error) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug(
          "[{}] Authorization Code Flow: sending response, error: {}",
          getAgentName(),
          error == null ? "none" : error.toString());
    }
    try {
      if (error == null) {
        writeResponse(exchange, HTTP_OK, HTML_TEMPLATE_OK);
      } else {
        writeResponse(exchange, HTTP_UNAUTHORIZED, HTML_TEMPLATE_FAILED, error.toString());
      }
    } catch (IOException e) {
      LOGGER.debug("[{}] Authorization Code Flow: error writing response", getAgentName(), e);
    }
    return null;
  }

  private String extractAuthorizationCode(HttpExchange exchange) {
    LOGGER.debug("[{}] Authorization Code Flow: extracting code", getAgentName());
    Map<String, List<String>> params =
        UriUtils.decodeParameters(exchange.getRequestURI().getRawQuery());
    List<String> states = params.getOrDefault("state", List.of());
    if (states.size() != 1 || !getState().equals(states.get(0))) {
      throw new IllegalArgumentException("Missing or invalid state");
    }
    List<String> codes = params.getOrDefault("code", List.of());
    if (codes.size() != 1) {
      throw new IllegalArgumentException("Missing or invalid authorization code");
    }
    return codes.get(0);
  }

  private CompletionStage<Tokens> fetchNewTokens(String code) {
    LOGGER.debug("[{}] Authorization Code Flow: fetching new tokens", getAgentName());
    AuthorizationCodeTokenRequest.Builder request =
        AuthorizationCodeTokenRequest.builder().code(code).redirectUri(getRedirectUri());
    String codeVerifier = getCodeVerifier();
    if (codeVerifier != null) {
      request.codeVerifier(codeVerifier);
    }
    return invokeTokenEndpoint(null, request);
  }

  private void log(Throwable error) {
    if (LOGGER.isDebugEnabled()) {
      if (error == null) {
        LOGGER.debug("[{}] Authorization Code Flow: tokens received", getAgentName());
      } else {
        LOGGER.debug(
            "[{}] Authorization Code Flow: error fetching tokens: {}",
            getAgentName(),
            error.toString());
      }
    }
  }

  @SuppressWarnings("HttpUrlsUsage")
  private static URI defaultRedirectUri(String bindHost, int bindPort, String contextPath) {
    return URI.create(java.lang.String.format("http://%s:%d/%s", bindHost, bindPort, contextPath))
        .normalize();
  }

  private static HttpServer createServer(
      String hostname, int port, String contextPath, HttpHandler handler) {
    try {
      HttpServer server = HttpServer.create(new InetSocketAddress(hostname, port), 0);
      server.createContext(contextPath, handler);
      server.start();
      return server;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  @FormatMethod
  private static void writeResponse(
      HttpExchange exchange, int status, String htmlTemplate, Object... args) throws IOException {
    String html = String.format(htmlTemplate, args);
    exchange.getResponseHeaders().add("Content-Type", "text/html");
    exchange.sendResponseHeaders(status, html.length());
    exchange.getResponseBody().write(html.getBytes(StandardCharsets.UTF_8));
  }
}

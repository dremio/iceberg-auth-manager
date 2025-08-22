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

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.crypto.PemReader;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import java.net.URI;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Infrastructure shared by all flows. */
abstract class AbstractFlow implements Flow {

  static final String OAUTH2_AGENT_TITLE = "======== Authentication Required ========";
  static final String OAUTH2_AGENT_OPEN_URL = "Please open the following URL to continue:";

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFlow.class);

  static String getContextPath(String agentName) {
    return '/' + agentName + "/auth";
  }

  static String getMsgPrefix(String agentName) {
    return '[' + agentName + "] ";
  }

  interface Builder<F extends AbstractFlow, B extends Builder<F, B>> {

    @CanIgnoreReturnValue
    B config(OAuth2Config config);

    @CanIgnoreReturnValue
    B runtime(OAuth2AgentRuntime runtime);

    @CanIgnoreReturnValue
    B requestSender(HTTPRequestSender requestSender);

    @CanIgnoreReturnValue
    B endpointProvider(EndpointProvider endpointProvider);

    F build();
  }

  abstract OAuth2Config getConfig();

  abstract OAuth2AgentRuntime getRuntime();

  abstract HTTPRequestSender getRequestSender();

  abstract EndpointProvider getEndpointProvider();

  CompletionStage<TokensResult> invokeTokenEndpoint(AuthorizationGrant grant) {
    TokenRequest.Builder builder = newTokenRequestBuilder(grant);
    HTTPRequest request = builder.build().toHTTPRequest();
    return CompletableFuture.supplyAsync(() -> sendAndReceive(request), getRuntime().getExecutor())
        .whenComplete((response, error) -> log(request, response, error))
        .thenApply(this::parseTokenResponse)
        .thenApply(this::toTokensResult);
  }

  TokenRequest.Builder newTokenRequestBuilder(AuthorizationGrant grant) {
    URI tokenEndpoint = getEndpointProvider().getResolvedTokenEndpoint();
    ClientID clientID = getConfig().getBasicConfig().getClientId().orElseThrow();
    TokenRequest.Builder builder =
        isPublicClient()
            ? new TokenRequest.Builder(tokenEndpoint, clientID, grant)
            : new TokenRequest.Builder(tokenEndpoint, createClientAuthentication(), grant);
    getConfig().getBasicConfig().getScope().ifPresent(builder::scope);
    getConfig().getBasicConfig().getExtraRequestParameters().forEach(builder::customParameter);
    return builder;
  }

  HTTPResponse sendAndReceive(HTTPRequest request) {
    try {
      LOGGER.debug(
          "[{}] Invoking endpoint: {}",
          getConfig().getSystemConfig().getAgentName(),
          request.getURI());
      return request.send(getRequestSender());
    } catch (Exception e) {
      throw new RuntimeException("Failed to invoke endpoint: " + request.getURI(), e);
    }
  }

  AccessTokenResponse parseTokenResponse(HTTPResponse httpResponse) {
    try {
      TokenResponse response = TokenResponse.parse(httpResponse);
      if (!response.indicatesSuccess()) {
        TokenErrorResponse errorResponse = response.toErrorResponse();
        throw new OAuth2Exception(errorResponse);
      }
      return response.toSuccessResponse();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }

  TokensResult toTokensResult(AccessTokenResponse response) {
    Instant now = getRuntime().getClock().instant();
    return TokensResult.of(response, now);
  }

  void log(HTTPRequest request, HTTPResponse response, Throwable error) {
    String agentName = getConfig().getSystemConfig().getAgentName();
    if (error == null) {
      LOGGER.debug(
          "[{}] Received {} response from endpoint: {}",
          agentName,
          response.getStatusCode(),
          request.getURI());
    } else {
      LOGGER.warn("[{}] Error invoking endpoint: {}", agentName, request.getURI(), error);
    }
  }

  boolean isPublicClient() {
    return getConfig()
        .getBasicConfig()
        .getClientAuthenticationMethod()
        .equals(ClientAuthenticationMethod.NONE);
  }

  ClientAuthentication createClientAuthentication() {
    URI tokenEndpoint = getEndpointProvider().getResolvedTokenEndpoint();

    ClientAuthenticationMethod method =
        getConfig().getBasicConfig().getClientAuthenticationMethod();

    if (method.equals(CLIENT_SECRET_BASIC)) {
      return new ClientSecretBasic(
          getConfig().getBasicConfig().getClientId().orElseThrow(),
          getConfig().getBasicConfig().getClientSecret().orElseThrow());

    } else if (method.equals(CLIENT_SECRET_POST)) {
      return new ClientSecretPost(
          getConfig().getBasicConfig().getClientId().orElseThrow(),
          getConfig().getBasicConfig().getClientSecret().orElseThrow());

    } else if (method.equals(CLIENT_SECRET_JWT)) {
      JWTAssertionDetails details = createJwtAssertionDetails(tokenEndpoint);
      JWSAlgorithm algorithm =
          getConfig().getClientAssertionConfig().getAlgorithm().orElse(JWSAlgorithm.HS256);
      Secret secret = getConfig().getBasicConfig().getClientSecret().orElseThrow();
      try {
        SignedJWT assertion = JWTAssertionFactory.create(details, algorithm, secret);
        return new ClientSecretJWT(assertion);
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }

    } else if (method.equals(PRIVATE_KEY_JWT)) {
      JWTAssertionDetails details = createJwtAssertionDetails(tokenEndpoint);
      JWSAlgorithm algorithm =
          getConfig().getClientAssertionConfig().getAlgorithm().orElse(JWSAlgorithm.RS256);
      Path privateKeyPath = getConfig().getClientAssertionConfig().getPrivateKey().orElseThrow();
      PrivateKey privateKey = PemReader.getInstance().readPrivateKey(privateKeyPath);
      try {
        SignedJWT assertion =
            JWTAssertionFactory.create(details, algorithm, privateKey, null, null, null, null);
        return new PrivateKeyJWT(assertion);
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }
    }

    throw new IllegalArgumentException("Unsupported client authentication method: " + method);
  }

  private JWTAssertionDetails createJwtAssertionDetails(URI tokenEndpoint) {
    Issuer issuer =
        getConfig().getClientAssertionConfig().getIssuer().isPresent()
            ? getConfig().getClientAssertionConfig().getIssuer().get()
            : new Issuer(getConfig().getBasicConfig().getClientId().orElseThrow());
    Subject subject =
        getConfig().getClientAssertionConfig().getSubject().isPresent()
            ? getConfig().getClientAssertionConfig().getSubject().get()
            : new Subject(getConfig().getBasicConfig().getClientId().orElseThrow().getValue());
    Audience audience =
        getConfig().getClientAssertionConfig().getAudience().isPresent()
            ? getConfig().getClientAssertionConfig().getAudience().get()
            : new Audience(tokenEndpoint);
    Instant issuedAt = getRuntime().getClock().instant();
    Instant expiration = issuedAt.plus(getConfig().getClientAssertionConfig().getTokenLifespan());
    @SuppressWarnings({"rawtypes", "unchecked"})
    Map<String, Object> extraClaims = (Map) getConfig().getClientAssertionConfig().getExtraClaims();
    return new JWTAssertionDetails(
        issuer,
        subject,
        List.of(audience),
        Date.from(expiration),
        Date.from(issuedAt),
        Date.from(issuedAt),
        new JWTID(),
        extraClaims);
  }
}

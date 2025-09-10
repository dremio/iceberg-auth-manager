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
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ErrorExpectation.AUTHORIZATION_SERVER_ERROR_RESPONSE;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.http.client.utils.URIBuilder;
import org.immutables.value.Value;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.Parameters;

@AuthManagerImmutable
@Value.Enclosing
public abstract class AuthorizationCodeExpectation extends InitialTokenFetchExpectation {

  /** A map of pending authorization requests, keyed by the redirect URI. */
  @Value.Lazy
  protected ConcurrentMap<String, AuthorizationCodeExpectation.PendingAuthRequest>
      getPendingAuthRequests() {
    return new ConcurrentHashMap<>();
  }

  @Override
  public void create() {
    createAuthEndpointExpectation();
    super.create();
  }

  @Override
  protected ImmutableMap.Builder<String, String> requestBody() {
    ImmutableMap.Builder<String, String> builder =
        super.requestBody()
            .put("grant_type", GrantType.AUTHORIZATION_CODE.toString())
            .put("code", "[a-zA-Z0-9-._~]+")
            .put("redirect_uri", "https?://.*");
    if (getTestEnvironment().isPkceEnabled()) {
      builder.put("code_verifier", "[a-zA-Z0-9-._~]+");
    }
    return builder;
  }

  @Override
  protected HttpResponse response(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    Map<String, List<String>> params = decodeBodyParameters(httpRequest);
    String redirectUri = params.get("redirect_uri").get(0);
    PendingAuthRequest pendingAuthRequest = getPendingAuthRequests().get(redirectUri);
    if (pendingAuthRequest == null) {
      return AUTHORIZATION_SERVER_ERROR_RESPONSE;
    }
    List<String> code = params.get("code");
    if (code == null
        || code.isEmpty()
        || !code.get(0).equals(pendingAuthRequest.getCode().getValue())) {
      return AUTHORIZATION_SERVER_ERROR_RESPONSE;
    }
    if (getTestEnvironment().isPkceEnabled()) {
      if (pendingAuthRequest.getCodeChallengeMethod().isEmpty()
          || pendingAuthRequest.getCodeChallenge().isEmpty()) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
      List<String> codeVerifier = params.get("code_verifier");
      if (codeVerifier == null || codeVerifier.isEmpty()) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
      if (!pendingAuthRequest
          .getCodeChallenge()
          .get()
          .equals(pendingAuthRequest.getCodeChallenge().get())) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
    }
    getPendingAuthRequests().remove(redirectUri);
    return super.response(httpRequest, accessToken, refreshToken);
  }

  private void createAuthEndpointExpectation() {
    HttpRequest request =
        HttpRequest.request()
            .withMethod("GET")
            .withPath(getTestEnvironment().getAuthorizationEndpoint().getPath())
            .withQueryStringParameter("response_type", "code")
            .withQueryStringParameter("client_id", String.format("(%s|%s)", CLIENT_ID1, CLIENT_ID2))
            .withQueryStringParameter("scope", String.format("(%s|%s)", SCOPE1, SCOPE2))
            .withQueryStringParameter(
                "redirect_uri", "https?://localhost:\\d+/iceberg-auth-manager-\\d+(-\\w+)?/auth")
            .withQueryStringParameter("state", "[a-zA-Z0-9-._~]+")
            .withQueryStringParameter("(extra1|extra2)", "(value1|value2)");
    if (getTestEnvironment().isPkceEnabled()) {
      request.withQueryStringParameter("code_challenge", "[a-zA-Z0-9-._~]+");
      request.withQueryStringParameter(
          "code_challenge_method", getTestEnvironment().getCodeChallengeMethod().getValue());
    }
    getClientAndServer()
        .when(request)
        .respond(
            httpRequest -> {
              Parameters parameters = httpRequest.getQueryStringParameters();
              String redirectUri = parameters.getValues("redirect_uri").get(0);
              AuthorizationCode code = new AuthorizationCode();
              String location =
                  new URIBuilder(redirectUri)
                      .addParameter("code", code.getValue())
                      .addParameter("state", parameters.getValues("state").get(0))
                      .build()
                      .toString();
              CodeChallengeMethod method = null;
              CodeChallenge codeChallenge = null;
              if (getTestEnvironment().isPkceEnabled()) {
                if (parameters.getValues("code_challenge_method").isEmpty()
                    || parameters.getValues("code_challenge").isEmpty()) {
                  return AUTHORIZATION_SERVER_ERROR_RESPONSE;
                }
                method =
                    CodeChallengeMethod.parse(parameters.getValues("code_challenge_method").get(0));
                codeChallenge = CodeChallenge.parse(parameters.getValues("code_challenge").get(0));
              }
              var pendingAuthRequest =
                  ImmutableAuthorizationCodeExpectation.PendingAuthRequest.builder()
                      .code(code)
                      .codeChallengeMethod(Optional.ofNullable(method))
                      .codeChallenge(Optional.ofNullable(codeChallenge))
                      .build();
              getPendingAuthRequests().put(redirectUri, pendingAuthRequest);
              return HttpResponse.response().withStatusCode(302).withHeader("Location", location);
            });
  }

  @AuthManagerImmutable
  public interface PendingAuthRequest {

    AuthorizationCode getCode();

    Optional<CodeChallengeMethod> getCodeChallengeMethod();

    Optional<CodeChallenge> getCodeChallenge();
  }
}

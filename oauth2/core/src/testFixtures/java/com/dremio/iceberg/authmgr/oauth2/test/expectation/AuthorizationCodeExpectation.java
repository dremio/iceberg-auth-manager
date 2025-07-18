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

import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableAuthorizationCodeTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
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
  protected PostFormRequest tokenRequestBody() {
    return ImmutableAuthorizationCodeTokenRequest.builder()
        .clientId(
            getTestEnvironment().isPrivateClient()
                ? null
                : String.format("(%s|%s)", CLIENT_ID1, CLIENT_ID2))
        .code("\\w{4}-\\w{4}")
        .redirectUri(URI.create("http://.*"))
        .scope(String.format("(%s|%s)", SCOPE1, SCOPE2))
        .putExtraParameter("(extra1|extra2)", "(value1|value2)")
        .build();
  }

  @Override
  protected HttpResponse tokenResponse(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    Map<String, List<String>> params = decodeBodyParameters(httpRequest);
    String redirectUri = params.get("redirect_uri").get(0);
    PendingAuthRequest pendingAuthRequest = getPendingAuthRequests().get(redirectUri);
    if (pendingAuthRequest == null) {
      return AUTHORIZATION_SERVER_ERROR_RESPONSE;
    }
    List<String> code = params.get("code");
    if (code == null || code.isEmpty() || !code.get(0).equals(pendingAuthRequest.getCode())) {
      return AUTHORIZATION_SERVER_ERROR_RESPONSE;
    }
    if (getTestEnvironment().isPkceEnabled()) {
      if (pendingAuthRequest.getPkceTransformation().isEmpty()
          || pendingAuthRequest.getPkceCodeChallenge().isEmpty()) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
      List<String> codeVerifier = params.get("code_verifier");
      if (codeVerifier == null || codeVerifier.isEmpty()) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
      String expectedCodeChallenge =
          FlowUtils.generateCodeChallenge(
              pendingAuthRequest.getPkceTransformation().get(), codeVerifier.get(0));
      if (!pendingAuthRequest.getPkceCodeChallenge().get().equals(expectedCodeChallenge)) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
    }
    getPendingAuthRequests().remove(redirectUri);
    return super.tokenResponse(httpRequest, accessToken, refreshToken);
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
                "redirect_uri", "http://localhost:\\d+/iceberg-auth-manager-\\w+(-\\w+)?/auth")
            .withQueryStringParameter("state", "\\w+");
    if (getTestEnvironment().isPkceEnabled()) {
      request.withQueryStringParameter("code_challenge", "[a-zA-Z0-9-._~]+");
      request.withQueryStringParameter(
          "code_challenge_method", getTestEnvironment().getPkceTransformation().getCanonicalName());
    }
    getClientAndServer()
        .when(request)
        .respond(
            httpRequest -> {
              Parameters parameters = httpRequest.getQueryStringParameters();
              String redirectUri = parameters.getValues("redirect_uri").get(0);
              String code =
                  FlowUtils.randomAlphaNumString(4) + "-" + FlowUtils.randomAlphaNumString(4);
              String location =
                  new UriBuilder(redirectUri)
                      .queryParam("code", code)
                      .queryParam("state", parameters.getValues("state").get(0))
                      .build()
                      .toString();
              PkceTransformation pkceTransformation = null;
              String codeChallenge = null;
              if (getTestEnvironment().isPkceEnabled()) {
                if (parameters.getValues("code_challenge_method").isEmpty()
                    || parameters.getValues("code_challenge").isEmpty()) {
                  return AUTHORIZATION_SERVER_ERROR_RESPONSE;
                }
                pkceTransformation =
                    PkceTransformation.fromConfigName(
                        parameters.getValues("code_challenge_method").get(0));
                codeChallenge = parameters.getValues("code_challenge").get(0);
              }
              var pendingAuthRequest =
                  ImmutableAuthorizationCodeExpectation.PendingAuthRequest.builder()
                      .code(code)
                      .pkceTransformation(Optional.ofNullable(pkceTransformation))
                      .pkceCodeChallenge(Optional.ofNullable(codeChallenge))
                      .build();
              getPendingAuthRequests().put(redirectUri, pendingAuthRequest);
              return HttpResponse.response().withStatusCode(302).withHeader("Location", location);
            });
  }

  @AuthManagerImmutable
  public interface PendingAuthRequest {

    String getCode();

    Optional<PkceTransformation> getPkceTransformation();

    Optional<String> getPkceCodeChallenge();
  }
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.AUTHORIZATION_CODE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ErrorExpectation.AUTHORIZATION_SERVER_ERROR_RESPONSE;

import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableAuthorizationCodeTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import com.dremio.iceberg.authmgr.oauth2.uri.UriUtils;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.Parameters;

@AuthManagerImmutable
public abstract class AuthorizationCodeExpectation extends InitialTokenFetchExpectation {

  @SuppressWarnings("immutables:incompat")
  private PkceTransformation pkceTransformation;

  @SuppressWarnings("immutables:incompat")
  private String pkceCodeChallenge;

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
        .code(AUTHORIZATION_CODE)
        .redirectUri(URI.create("http://.*"))
        .scope(String.format("(%s|%s)", SCOPE1, SCOPE2))
        .putExtraParameter("extra1", "value1")
        .build();
  }

  @Override
  protected HttpResponse tokenResponse(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    if (getTestEnvironment().isPkceEnabled()) {
      // See https://github.com/mock-server/mockserver/issues/1468
      String body = httpRequest.getBodyAsString();
      Map<String, List<String>> params = UriUtils.decodeParameters(body);
      List<String> codeVerifier = params.get("code_verifier");
      if (codeVerifier == null
          || codeVerifier.isEmpty()
          || !pkceCodeChallenge.equals(pkceTransformation.transform(codeVerifier.get(0)))) {
        return AUTHORIZATION_SERVER_ERROR_RESPONSE;
      }
    }
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
                "redirect_uri", "http://localhost:\\d+/oauth2-agent-\\w+/auth")
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
              String location =
                  new UriBuilder(parameters.getValues("redirect_uri").get(0))
                      .queryParam("code", AUTHORIZATION_CODE)
                      .queryParam("state", parameters.getValues("state").get(0))
                      .build()
                      .toString();
              if (getTestEnvironment().isPkceEnabled()) {
                if (parameters.getValues("code_challenge_method").isEmpty()
                    || parameters.getValues("code_challenge").isEmpty()) {
                  return AUTHORIZATION_SERVER_ERROR_RESPONSE;
                }
                pkceTransformation =
                    PkceTransformation.fromConfigName(
                        parameters.getValues("code_challenge_method").get(0));
                pkceCodeChallenge = parameters.getValues("code_challenge").get(0);
              }
              return HttpResponse.response().withStatusCode(302).withHeader("Location", location);
            });
  }
}

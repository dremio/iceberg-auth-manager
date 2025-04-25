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

import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getJsonBody;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getParameterBody;

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableTokenResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

public abstract class AbstractTokenEndpointExpectation extends AbstractExpectation {

  protected HttpRequest tokenRequestTemplate() {
    return HttpRequest.request()
        .withMethod("POST")
        .withPath(getTestEnvironment().getTokenEndpoint().getPath())
        .withHeader("Content-Type", "application/x-www-form-urlencoded")
        .withHeader("Accept", "application/json");
  }

  protected HttpRequest tokenRequest() {
    HttpRequest request = tokenRequestTemplate().withBody(getParameterBody(tokenRequestBody()));
    addRequestHeaders(request);
    return request;
  }

  protected void addRequestHeaders(HttpRequest request) {
    if (getTestEnvironment().isPrivateClient()) {
      request.withHeader(
          "Authorization",
          String.format(
              "Basic (%s|%s)",
              TestConstants.CLIENT_CREDENTIALS1_BASE_64,
              TestConstants.CLIENT_CREDENTIALS2_BASE_64));
    }
  }

  protected abstract PostFormRequest tokenRequestBody();

  protected HttpResponse tokenResponse(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    return HttpResponse.response()
        .withBody(getJsonBody(tokenResponseBody(accessToken, refreshToken).build()));
  }

  protected ImmutableTokenResponse.Builder tokenResponseBody(
      String accessToken, String refreshToken) {
    ImmutableTokenResponse.Builder responseBody =
        ImmutableTokenResponse.builder()
            .accessTokenPayload(accessToken)
            .accessTokenExpiresInSeconds(
                (int) getTestEnvironment().getAccessTokenLifespan().toSeconds())
            .tokenType("bearer");
    if (getTestEnvironment().isReturnRefreshTokens()
        && getTestEnvironment().getGrantType() != GrantType.CLIENT_CREDENTIALS) {
      responseBody
          .refreshTokenPayload(refreshToken)
          .refreshTokenExpiresInSeconds(
              (int) getTestEnvironment().getRefreshTokenLifespan().toSeconds());
    }
    if (getTestEnvironment().getGrantType() == GrantType.TOKEN_EXCHANGE) {
      // included for completeness, but not used
      responseBody.issuedTokenType(TypedToken.URN_ACCESS_TOKEN);
    }
    return responseBody;
  }
}

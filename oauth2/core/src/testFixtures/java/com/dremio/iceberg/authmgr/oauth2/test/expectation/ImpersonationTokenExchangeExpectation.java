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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.*;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_CREDENTIALS2_BASE_64;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getParameterBody;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableTokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableTokenResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;
import java.util.Map;
import org.mockserver.model.HttpRequest;

@AuthManagerImmutable
public abstract class ImpersonationTokenExchangeExpectation extends InitialTokenFetchExpectation {

  @Override
  public void create() {
    if (getTestEnvironment().isImpersonationEnabled()) {
      URI tokenEndpoint = getTestEnvironment().getImpersonationTokenEndpoint();
      HttpRequest request =
          HttpRequest.request()
              .withMethod("POST")
              .withPath(tokenEndpoint.getPath())
              .withHeader("Content-Type", "application/x-www-form-urlencoded")
              .withHeader("Accept", "application/json")
              .withBody(getParameterBody(tokenRequestBody()));
      if (getTestEnvironment().isPrivateClient()) {
        request.withHeader("Authorization", "Basic " + CLIENT_CREDENTIALS2_BASE_64);
      }
      getClientAndServer()
          .when(request)
          .respond(
              httpRequest ->
                  tokenResponse(httpRequest, "access_impersonated", "refresh_impersonated"));
    }
  }

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableTokenExchangeRequest.builder()
        .clientId(getTestEnvironment().isPrivateClient() ? null : CLIENT_ID2)
        .subjectToken(SUBJECT_TOKEN)
        .subjectTokenType(SUBJECT_TOKEN_TYPE)
        .actorToken(ACTOR_TOKEN)
        .actorTokenType(ACTOR_TOKEN_TYPE)
        .requestedTokenType(REQUESTED_TOKEN_TYPE)
        .audience(AUDIENCE)
        .resource(RESOURCE)
        .extraParameters(Map.of("impersonation", "true"))
        .build();
  }

  @Override
  protected ImmutableTokenResponse.Builder tokenResponseBody(
      String accessToken, String refreshToken) {
    return super.tokenResponseBody(accessToken, refreshToken)
        .accessTokenExpiresInSeconds(
            (int) getTestEnvironment().getImpersonationAccessTokenLifespan().toSeconds());
  }
}

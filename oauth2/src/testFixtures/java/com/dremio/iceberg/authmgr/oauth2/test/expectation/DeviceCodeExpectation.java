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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.DEVICE_CODE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.USER_CODE;
import static org.mockserver.model.Parameter.param;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableDeviceAccessTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableDeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.JsonBody;
import org.mockserver.model.MediaType;
import org.mockserver.model.ParameterBody;
import org.mockserver.model.StringBody;

@AuthManagerImmutable
public abstract class DeviceCodeExpectation extends InitialTokenFetchExpectation {

  @SuppressWarnings("immutables:incompat")
  private volatile boolean userCodeReceived;

  @Override
  public void create() {
    createDeviceAuthEndpointExpectation();
    createDeviceVerificationEndpointExpectation();
    getClientAndServer().when(tokenRequest()).respond(this::deviceAuthTokenResponse);
  }

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableDeviceAccessTokenRequest.builder()
        .clientId(getTestEnvironment().isPrivateClient() ? null : CLIENT_ID1)
        .deviceCode(DEVICE_CODE)
        .scope(SCOPE1)
        .putExtraParameter("extra1", "value1")
        .build();
  }

  private HttpResponse deviceAuthTokenResponse(HttpRequest httpRequest) {
    if (userCodeReceived) {
      return tokenResponse(httpRequest, "access_initial", "refresh_initial");
    } else {
      return HttpResponse.response()
          .withStatusCode(401)
          .withBody(
              JsonBody.json(
                  "{\"error\":\"authorization_pending\",\"error_description\":\"User code not yet received\"}"));
    }
  }

  private void createDeviceAuthEndpointExpectation() {
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withMethod("POST")
                .withPath(getTestEnvironment().getDeviceAuthorizationEndpoint().getPath())
                .withContentType(MediaType.APPLICATION_FORM_URLENCODED)
                .withBody(ParameterBody.params(param("scope", SCOPE1))))
        .respond(
            HttpResponse.response()
                .withBody(
                    JsonBody.json(
                        ImmutableDeviceAuthorizationResponse.builder()
                            .deviceCode(DEVICE_CODE)
                            .userCode(USER_CODE)
                            .verificationUri(getTestEnvironment().getDeviceVerificationEndpoint())
                            .verificationUriComplete(
                                getTestEnvironment().getDeviceVerificationEndpoint())
                            .expiresInSeconds(300)
                            .intervalSeconds(1)
                            .build())));
  }

  private void createDeviceVerificationEndpointExpectation() {
    String path = getTestEnvironment().getDeviceVerificationEndpoint().getPath();
    // Expect the device verification page to be opened in a browser
    getClientAndServer()
        .when(HttpRequest.request().withMethod("GET").withPath(path))
        .respond(
            HttpResponse.response()
                .withBody(
                    // Send a dummy HTML page to simulate the user interaction;
                    // the actual content is not important for the test.
                    StringBody.exact(
                        "<html><body>Enter device code:"
                            + "<form method=\"POST\" action=\""
                            + path
                            + "\">"
                            + "<input type=\"text\" name=\"device_user_code\" />"
                            + "<input type=\"submit\" value=\"Submit\" />"
                            + "</form>"
                            + "</body></html>",
                        MediaType.TEXT_HTML)));
    // Expect the device verification code to be sent by the user after opening the page
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withMethod("POST")
                .withPath(path)
                .withContentType(MediaType.APPLICATION_FORM_URLENCODED)
                .withBody(ParameterBody.params(param("device_user_code", USER_CODE))))
        .respond(
            httpRequest -> {
              userCodeReceived = true;
              return HttpResponse.response()
                  .withBody(
                      StringBody.exact(
                          "<html><body>Device authorized</body></html>", MediaType.TEXT_HTML));
            });
  }
}

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
import static org.mockserver.model.Parameter.param;

import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableDeviceAccessTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableDeviceAuthorizationResponse;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.immutables.value.Value;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.JsonBody;
import org.mockserver.model.MediaType;
import org.mockserver.model.ParameterBody;
import org.mockserver.model.StringBody;

@AuthManagerImmutable
public abstract class DeviceCodeExpectation extends InitialTokenFetchExpectation {

  /** A map of pending authorization requests, keyed by the user and device code. */
  @Value.Lazy
  protected ConcurrentMap<String, DeviceCodeExpectation.PendingAuthRequest>
      getPendingAuthRequests() {
    return new ConcurrentHashMap<>();
  }

  @Override
  public void create() {
    createDeviceAuthEndpointExpectation();
    createDeviceVerificationEndpointExpectation();
    super.create();
  }

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableDeviceAccessTokenRequest.builder()
        .clientId(
            getTestEnvironment().isPrivateClient()
                ? null
                : String.format("(%s|%s)", CLIENT_ID1, CLIENT_ID2))
        .deviceCode("\\w{8}-\\w{8}")
        .scope(String.format("(%s|%s)", SCOPE1, SCOPE2))
        .putExtraParameter("(extra1|extra2)", "(value1|value2)")
        .build();
  }

  @Override
  protected HttpResponse tokenResponse(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    Map<String, List<String>> params = decodeBodyParameters(httpRequest);
    String deviceCode = params.get("device_code").get(0);
    PendingAuthRequest pendingAuthRequest = getPendingAuthRequests().get(deviceCode);
    if (pendingAuthRequest.isUserCodeReceived()) {
      getPendingAuthRequests().remove(pendingAuthRequest.getDeviceCode());
      getPendingAuthRequests().remove(pendingAuthRequest.getUserCode());
      return super.tokenResponse(httpRequest, accessToken, refreshToken);
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
                .withBody(
                    ParameterBody.params(param("scope", String.format("(%s|%s)", SCOPE1, SCOPE2)))))
        .respond(
            httpRequest -> {
              String userCode =
                  FlowUtils.randomAlphaNumString(4) + "-" + FlowUtils.randomAlphaNumString(4);
              String deviceCode =
                  FlowUtils.randomAlphaNumString(8) + "-" + FlowUtils.randomAlphaNumString(8);
              var pendingAuthRequest = new PendingAuthRequest(userCode, deviceCode);
              getPendingAuthRequests().put(userCode, pendingAuthRequest);
              getPendingAuthRequests().put(deviceCode, pendingAuthRequest);
              return HttpResponse.response()
                  .withBody(
                      JsonBody.json(
                          ImmutableDeviceAuthorizationResponse.builder()
                              .deviceCode(deviceCode)
                              .userCode(userCode)
                              .verificationUri(getTestEnvironment().getDeviceVerificationEndpoint())
                              .verificationUriComplete(
                                  getTestEnvironment().getDeviceVerificationEndpoint())
                              .expiresInSeconds(300)
                              .intervalSeconds(1)
                              .build()));
            });
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
                .withBody(ParameterBody.params(param("device_user_code", "\\w{4}-\\w{4}"))))
        .respond(
            httpRequest -> {
              // See https://github.com/mock-server/mockserver/issues/1468
              Map<String, List<String>> params = decodeBodyParameters(httpRequest);
              List<String> userCode = params.get("device_user_code");
              if (userCode == null || userCode.isEmpty()) {
                return AUTHORIZATION_SERVER_ERROR_RESPONSE;
              }
              PendingAuthRequest pendingAuthRequest = getPendingAuthRequests().get(userCode.get(0));
              if (pendingAuthRequest == null) {
                return AUTHORIZATION_SERVER_ERROR_RESPONSE;
              }
              pendingAuthRequest.setUserCodeReceived(true);
              return HttpResponse.response()
                  .withBody(
                      StringBody.exact(
                          "<html><body>Device authorized</body></html>", MediaType.TEXT_HTML));
            });
  }

  public static final class PendingAuthRequest {

    private final String userCode;
    private final String deviceCode;

    private volatile boolean userCodeReceived;

    public PendingAuthRequest(String userCode, String deviceCode) {
      this.userCode = userCode;
      this.deviceCode = deviceCode;
    }

    public String getUserCode() {
      return userCode;
    }

    public String getDeviceCode() {
      return deviceCode;
    }

    public boolean isUserCodeReceived() {
      return userCodeReceived;
    }

    public void setUserCodeReceived(boolean userCodeReceived) {
      this.userCodeReceived = userCodeReceived;
    }
  }
}

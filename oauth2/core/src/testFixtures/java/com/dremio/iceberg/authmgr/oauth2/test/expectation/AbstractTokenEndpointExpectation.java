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
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET2;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getJsonBody;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.mockserver.model.Header;
import org.mockserver.model.HttpMessage;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

public abstract class AbstractTokenEndpointExpectation extends AbstractExpectation {

  protected HttpRequest request() {
    URI tokenEndpoint = getTestEnvironment().getTokenEndpoint();
    String path =
        tokenEndpoint.isAbsolute()
            ? tokenEndpoint.getPath()
            : getTestEnvironment().getCatalogServerContextPath() + tokenEndpoint.getPath();
    return HttpRequest.request()
        .withMethod("POST")
        .withPath(path)
        .withHeader("Content-Type", "application/x-www-form-urlencoded(; charset=UTF-8)?")
        .withHeader("Accept", "application/json")
        .withHeaders(requestHeaders().build())
        .withBody(ExpectationUtils.getParameterBody(requestBody().build()));
  }

  protected HttpResponse response(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    return HttpResponse.response()
        .withBody(getJsonBody(responseBody(accessToken, refreshToken).build()));
  }

  protected ImmutableList.Builder<Header> requestHeaders() {
    ImmutableList.Builder<Header> builder = ImmutableList.builder();
    if (getTestEnvironment()
        .getClientAuthenticationMethod()
        .equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
      builder.add(
          new Header(
              "Authorization",
              String.format(
                  "Basic (%s|%s)",
                  TestConstants.CLIENT_CREDENTIALS1_BASE_64,
                  TestConstants.CLIENT_CREDENTIALS2_BASE_64)));
    }
    return builder;
  }

  protected ImmutableMap.Builder<String, String> requestBody() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder().put("(extra1|extra2)", "(value1|value2)");
    if (getTestEnvironment()
        .getClientAuthenticationMethod()
        .equals(ClientAuthenticationMethod.NONE)) {
      builder.put("client_id", String.format("(%s|%s)", CLIENT_ID1, CLIENT_ID2));
    } else if (getTestEnvironment()
        .getClientAuthenticationMethod()
        .equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
      builder.put("client_id", String.format("(%s|%s)", CLIENT_ID1, CLIENT_ID2));
      builder.put(
          "client_secret",
          String.format("(%s|%s)", CLIENT_SECRET1.getValue(), CLIENT_SECRET2.getValue()));
    }
    return builder;
  }

  protected ImmutableMap.Builder<String, Object> responseBody(
      String accessToken, String refreshToken) {
    ImmutableMap.Builder<String, Object> builder =
        ImmutableMap.<String, Object>builder()
            .put("access_token", accessToken)
            .put("token_type", "bearer")
            .put("expires_in", getTestEnvironment().getAccessTokenLifespan().toSeconds());
    if (getTestEnvironment().isReturnRefreshTokens()) {
      builder.put("refresh_token", refreshToken);
      if (getTestEnvironment().isReturnRefreshTokenLifespan()) {
        builder.put(
            "refresh_expires_in", getTestEnvironment().getRefreshTokenLifespan().toSeconds());
      }
    }
    if (getTestEnvironment().getGrantType().equals(GrantType.TOKEN_EXCHANGE)) {
      // included for completeness, but not used
      builder.put("issued_token_type", TokenTypeURI.ACCESS_TOKEN.toString());
    }
    return builder;
  }

  protected static Map<String, List<String>> decodeBodyParameters(HttpMessage<?, ?> httpMessage) {
    // See https://github.com/mock-server/mockserver/issues/1468
    String body = httpMessage.getBodyAsString();
    return URLUtils.parseParameters(body);
  }
}

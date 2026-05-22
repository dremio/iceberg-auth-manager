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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_INITIAL;

import com.dremio.iceberg.authmgr.oauth2.test.TestServer;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

public abstract class InitialTokenFetchExpectation extends AbstractTokenEndpointExpectation {

  @Override
  public void create() {
    TestServer.getInstance()
        .when(request())
        .respond(httpRequest -> response(httpRequest, ACCESS_TOKEN_INITIAL, REFRESH_TOKEN_INITIAL));
  }

  @Override
  protected HttpResponse response(
      HttpRequest httpRequest, String accessToken, String refreshToken) {
    if (getTestEnvironment().isDpopEnabled()
        && getTestEnvironment().isRequireDpopNonce()
        && !hasDpopNonce(httpRequest)) {
      // Simulate an AS that demands a DPoP nonce (RFC 9449 §8)
      return HttpResponse.response()
          .withStatusCode(400)
          .withHeader("Content-Type", "application/json")
          .withHeader("DPoP-Nonce", getTestEnvironment().getDpopNonce())
          .withBody("{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}");
    }
    return super.response(httpRequest, accessToken, refreshToken);
  }

  private static boolean hasDpopNonce(HttpRequest httpRequest) {
    String dpopHeader = httpRequest.getFirstHeader("DPoP");
    if (dpopHeader == null || dpopHeader.isEmpty()) {
      return false;
    }
    try {
      return SignedJWT.parse(dpopHeader).getJWTClaimsSet().getStringClaim("nonce") != null;
    } catch (ParseException e) {
      return false;
    }
  }
}

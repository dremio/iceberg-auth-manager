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
package com.dremio.iceberg.authmgr.oauth2.test.user;

import static com.dremio.iceberg.authmgr.oauth2.uri.UriUtils.decodeParameters;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A user flow for Authorization Code flows that is compatible with Keycloak. */
@AuthManagerImmutable
public abstract class AuthorizationCodeUserFlow extends UserFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeUserFlow.class);

  @Override
  public void run() {
    try {
      LOGGER.debug("Starting authorization code user flow.");
      Set<String> cookies = new HashSet<>();
      URI callbackUri;
      if (getUserBehavior().getUsername().isEmpty()) {
        HttpURLConnection conn = (HttpURLConnection) getAuthUrl().toURL().openConnection();
        callbackUri = readRedirectUrl(conn, cookies);
        conn.disconnect();
      } else {
        var username = getUserBehavior().getRequiredUsername();
        var password = getUserBehavior().getRequiredPassword();
        callbackUri = login(getAuthUrl(), username, password, cookies);
      }
      invokeCallbackUrl(callbackUri);
      LOGGER.debug("Authorization code user flow completed.");
    } catch (Exception | AssertionError t) {
      getErrorListener().accept(t);
    }
  }

  /** Emulate browser being redirected to callback URL. */
  private void invokeCallbackUrl(URI callbackUrl) throws Exception {
    LOGGER.debug("Opening callback URL...");
    assertThat(callbackUrl).hasParameter("code").hasParameter("state");
    boolean useWrongCode = getUserBehavior().isEmulateFailure();
    if (useWrongCode) {
      Map<String, List<String>> params = decodeParameters(callbackUrl.getQuery());
      assertThat(params.get("state")).hasSize(1);
      callbackUrl =
          new UriBuilder(callbackUrl)
              .clearQueryParams()
              .queryParam("code", "WRONG-CODE")
              .queryParam("state", params.get("state").get(0))
              .build();
    }
    HttpURLConnection conn = (HttpURLConnection) callbackUrl.toURL().openConnection();
    conn.setRequestMethod("GET");
    int status = conn.getResponseCode();
    conn.disconnect();
    assertThat(status).isEqualTo(useWrongCode ? HTTP_UNAUTHORIZED : HTTP_OK);
  }
}

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
package com.dremio.iceberg.authmgr.oauth2.test.user;

import static com.dremio.iceberg.authmgr.oauth2.uri.UriUtils.decodeParameters;
import static java.net.HttpURLConnection.HTTP_OK;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakAuthCodeUserEmulator extends AbstractKeycloakUserEmulator {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthCodeUserEmulator.class);

  private final String msgPrefix;
  private final String contextPath;

  private URI authUrl;

  private volatile String authorizationCodeOverride;
  private volatile int expectedCallbackStatus = HTTP_OK;

  /** Creates a new emulator with implicit login (for unit tests). */
  public KeycloakAuthCodeUserEmulator(String agentName) {
    this(agentName, null, null);
  }

  /**
   * Creates a new emulator with required user login using the given username and password (for
   * integration tests).
   */
  public KeycloakAuthCodeUserEmulator(String agentName, String username, String password) {
    super(agentName, username, password);
    msgPrefix = FlowUtils.getMsgPrefix(agentName);
    contextPath = FlowUtils.getContextPath(agentName);
  }

  public void overrideAuthorizationCode(String code, int expectedStatus) {
    authorizationCodeOverride = code;
    expectedCallbackStatus = expectedStatus;
  }

  @Override
  protected Runnable processLine(String line) {
    if (line.startsWith(msgPrefix) && line.contains("http")) {
      authUrl = extractAuthUrl(line);
      return this::triggerAuthorizationCodeFlow;
    }
    return null;
  }

  /**
   * Emulate user browsing to the authorization URL printed on the console, then following the
   * instructions and optionally logging in with their credentials.
   */
  private void triggerAuthorizationCodeFlow() {
    try {
      LOGGER.debug("Starting authorization code flow.");
      Set<String> cookies = new HashSet<>();
      URI callbackUri;
      if (username == null || password == null) {
        HttpURLConnection conn = (HttpURLConnection) authUrl.toURL().openConnection();
        callbackUri = readRedirectUrl(conn, cookies);
        conn.disconnect();
      } else {
        callbackUri = login(authUrl, cookies);
      }
      invokeCallbackUrl(callbackUri);
      LOGGER.debug("Authorization code flow completed.");
    } catch (Exception | AssertionError t) {
      recordFailure(t);
    }
  }

  /** Emulate browser being redirected to callback URL. */
  private void invokeCallbackUrl(URI callbackUrl) throws Exception {
    LOGGER.debug("Opening callback URL...");
    assertThat(callbackUrl).hasPath(contextPath).hasParameter("code").hasParameter("state");
    if (authorizationCodeOverride != null) {
      Map<String, List<String>> params = decodeParameters(callbackUrl.getQuery());
      assertThat(params.get("state")).hasSize(1);
      callbackUrl =
          new UriBuilder(callbackUrl)
              .clearQueryParams()
              .queryParam("code", authorizationCodeOverride)
              .queryParam("state", params.get("state").get(0))
              .build();
    }
    HttpURLConnection conn = (HttpURLConnection) callbackUrl.toURL().openConnection();
    conn.setRequestMethod("GET");
    int status = conn.getResponseCode();
    conn.disconnect();
    assertThat(status).isEqualTo(expectedCallbackStatus);
  }
}

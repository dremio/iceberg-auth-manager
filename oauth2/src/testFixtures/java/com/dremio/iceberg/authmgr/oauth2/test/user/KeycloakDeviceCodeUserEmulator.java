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

import static java.net.HttpURLConnection.HTTP_OK;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.google.common.collect.ImmutableMap;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakDeviceCodeUserEmulator extends AbstractKeycloakUserEmulator {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(KeycloakDeviceCodeUserEmulator.class);

  private static final Pattern FORM_ACTION_PATTERN =
      Pattern.compile("<form.*action=\"([^\"]+)\".*>");

  private static final Pattern HIDDEN_CODE_PATTERN =
      Pattern.compile("<input type=\"hidden\" name=\"code\" value=\"([^\"]+)\">");

  private final String msgPrefix;
  private final Pattern userCodePattern;

  private URI authUrl;
  private String userCode;

  private volatile boolean denyConsent = false;

  /** Creates a new emulator with implicit login (for unit tests). */
  public KeycloakDeviceCodeUserEmulator(String agentName) {
    this(agentName, null, null);
  }

  /**
   * Creates a new emulator with required user login using the given username and password (for
   * integration tests).
   */
  public KeycloakDeviceCodeUserEmulator(String agentName, String username, String password) {
    super(agentName, username, password);
    msgPrefix = FlowUtils.getMsgPrefix(agentName);
    userCodePattern = Pattern.compile(Pattern.quote(msgPrefix) + "\\w{4}-\\w{4}");
  }

  public void denyConsent() {
    this.denyConsent = true;
  }

  @Override
  protected Runnable processLine(String line) {
    if (line.startsWith(msgPrefix) && line.contains("http")) {
      authUrl = extractAuthUrl(line);
    }
    if (userCodePattern.matcher(line).matches()) {
      assertThat(authUrl).isNotNull();
      userCode = line.substring(msgPrefix.length());
      return this::triggerDeviceCodeFlow;
    }
    return null;
  }

  /**
   * Emulate user browsing to the authorization URL printed on the console, then following the
   * instructions, entering the user code and optionally logging in with their credentials.
   */
  private void triggerDeviceCodeFlow() {
    try {
      LOGGER.debug("Starting device code flow.");
      Set<String> cookies = new HashSet<>();
      URI loginPageUrl = enterUserCode(authUrl, userCode, cookies);
      if (loginPageUrl != null) {
        URI consentPageUrl = login(loginPageUrl, cookies);
        authorizeDevice(consentPageUrl, cookies);
      }
      LOGGER.debug("Device code flow completed.");
    } catch (Exception | AssertionError t) {
      recordFailure(t);
    }
  }

  /** Emulate user entering provided user code on the authorization server. */
  private URI enterUserCode(URI codePageUrl, String userCode, Set<String> cookies)
      throws Exception {
    LOGGER.debug("Entering user code...");
    // receive device code page
    getHtmlPage(codePageUrl, cookies);
    // send device code form to same URL but with POST
    HttpURLConnection codeActionConn = openConnection(codePageUrl);
    Map<String, String> data = ImmutableMap.of("device_user_code", userCode);
    postForm(codeActionConn, data, cookies);
    URI loginUrl;
    if (username != null && password != null) {
      // Expect a redirect to the login page
      loginUrl = readRedirectUrl(codeActionConn, cookies);
    } else {
      // Unit tests: expect just a 200 OK
      assertThat(codeActionConn.getResponseCode()).isEqualTo(HTTP_OK);
      loginUrl = null;
    }
    codeActionConn.disconnect();
    return loginUrl;
  }

  /** Emulate user consenting to authorize device on the authorization server. */
  private void authorizeDevice(URI consentPageUrl, Set<String> cookies) throws Exception {
    LOGGER.debug("Authorizing device...");
    // receive consent page
    String consentHtml = getHtmlPage(consentPageUrl, cookies);
    Matcher matcher = FORM_ACTION_PATTERN.matcher(consentHtml);
    assertThat(matcher.find()).isTrue();
    URI formAction = URI.create(matcher.group(1));
    matcher = HIDDEN_CODE_PATTERN.matcher(consentHtml);
    assertThat(matcher.find()).isTrue();
    String deviceCode = matcher.group(1);
    // send consent form
    URI consentActionUrl =
        new URI(
            consentPageUrl.getScheme(),
            null,
            consentPageUrl.getHost(),
            consentPageUrl.getPort(),
            formAction.getPath(),
            formAction.getQuery(),
            null);
    HttpURLConnection consentActionConn = openConnection(consentActionUrl);
    Map<String, String> data =
        denyConsent
            ? ImmutableMap.of("code", deviceCode, "cancel", "No")
            : ImmutableMap.of("code", deviceCode, "accept", "Yes");
    postForm(consentActionConn, data, cookies);
    // Read the response but discard it, as it points to a static success HTML page
    readRedirectUrl(consentActionConn, cookies);
    consentActionConn.disconnect();
  }
}

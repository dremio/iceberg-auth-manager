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

import static java.net.HttpURLConnection.HTTP_OK;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import jakarta.annotation.Nullable;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A user flow for Device Code flows that understands the Keycloak-specific HTML forms. */
@AuthManagerImmutable
public abstract class DeviceCodeUserFlow extends UserFlow {

  private static final Logger LOGGER = LoggerFactory.getLogger(DeviceCodeUserFlow.class);

  private static final Pattern FORM_ACTION_PATTERN =
      Pattern.compile("<form.*action=\"([^\"]+)\".*>");

  private static final Pattern HIDDEN_CODE_PATTERN =
      Pattern.compile("<input type=\"hidden\" name=\"code\" value=\"([^\"]+)\">");

  protected abstract String getUserCode();

  @Override
  public void run() {
    try {
      LOGGER.debug("Starting device code user flow.");
      Set<String> cookies = new HashSet<>();
      URI loginPageUrl = enterUserCode(getAuthUrl(), getUserCode(), cookies);
      if (loginPageUrl != null) {
        var username = getUserBehavior().getRequiredUsername();
        var password = getUserBehavior().getRequiredPassword();
        URI consentPageUrl = login(loginPageUrl, username, password, cookies);
        authorizeDevice(consentPageUrl, cookies);
      }
      LOGGER.debug("Device code user flow completed.");
    } catch (Exception | AssertionError t) {
      getErrorListener().accept(t);
    }
  }

  /** Emulates user entering provided user code on the authorization server. */
  @Nullable
  private URI enterUserCode(URI codePageUrl, String userCode, Set<String> cookies)
      throws Exception {
    LOGGER.debug("Entering user code...");
    // receive device code page (and discard the HTML content)
    getHtmlPage(codePageUrl, cookies);
    // send device code form to same URL but with POST
    HttpURLConnection codeActionConn = openConnection(codePageUrl);
    // Emulate a failure at this step for unit tests only; for integration tests, we'll do it later
    boolean wrongCode =
        getUserBehavior().isEmulateFailure() && getUserBehavior().getUsername().isEmpty();
    Map<String, String> data =
        ImmutableMap.of("device_user_code", wrongCode ? "wrong_code" : userCode);
    postForm(codeActionConn, data, cookies);
    URI loginUrl = null;
    if (wrongCode) {
      assertThat(codeActionConn.getResponseCode()).isEqualTo(HttpURLConnection.HTTP_UNAUTHORIZED);
    } else {
      if (getUserBehavior().getUsername().isEmpty()) {
        // Unit tests: expect just a 200 OK
        assertThat(codeActionConn.getResponseCode()).isEqualTo(HTTP_OK);
      } else {
        // Expect a redirect to the login page
        loginUrl = readRedirectUrl(codeActionConn, cookies);
      }
    }
    codeActionConn.disconnect();
    return loginUrl;
  }

  /** Emulates user consenting to authorize device on the authorization server. */
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
    boolean denyConsent = getUserBehavior().isEmulateFailure();
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

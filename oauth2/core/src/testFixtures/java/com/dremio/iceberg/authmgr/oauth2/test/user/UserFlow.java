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

import static java.net.HttpURLConnection.HTTP_MOVED_PERM;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_SEE_OTHER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableMap;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A runnable that emulates a user browsing to the authorization URL printed on the console, then
 * following the instructions and optionally logging in with their credentials.
 *
 * <p>This implementation understands the HTML forms used by Keycloak.
 */
public abstract class UserFlow implements Runnable {

  private static final Logger LOGGER = LoggerFactory.getLogger(UserFlow.class);

  private static final Pattern LOGIN_FORM_ACTION_PATTERN =
      Pattern.compile("<form.*action=\"([^\"]+)\".*>");

  /** The authorization URL to browse to. */
  protected abstract URI getAuthUrl();

  /** The user behavior. */
  protected abstract UserBehavior getUserBehavior();

  /**
   * Callback to invoke when an error occurs. Allows signaling user flow failures back to the user
   * emulator thread.
   */
  protected abstract Consumer<Throwable> getErrorListener();

  /** The SSL context to use for HTTPS requests. */
  protected abstract Optional<SSLContext> getSslContext();

  /**
   * Emulates the user logging in to the authorization server. This method is only called for
   * integration tests.
   */
  protected URI login(URI loginPageUrl, String username, String password, Set<String> cookies)
      throws Exception {
    LOGGER.debug("Performing login...");
    // receive login page
    String loginHtml = getHtmlPage(loginPageUrl, cookies);
    Matcher matcher = LOGIN_FORM_ACTION_PATTERN.matcher(loginHtml);
    assertThat(matcher.find()).isTrue();
    URI loginActionUrl = new URI(matcher.group(1));
    // send login form
    HttpURLConnection loginActionConn = openConnection(loginActionUrl);
    Map<String, String> data =
        ImmutableMap.of(
            "username", username,
            "password", password,
            "credentialId", "");
    postForm(loginActionConn, data, cookies);
    URI redirectUrl = readRedirectUrl(loginActionConn, cookies);
    loginActionConn.disconnect();
    return redirectUrl;
  }

  protected String getHtmlPage(URI url, Set<String> cookies) throws Exception {
    HttpURLConnection conn = openConnection(url);
    conn.setRequestMethod("GET");
    writeCookies(conn, cookies);
    String html = readBody(conn);
    assertThat(conn.getResponseCode()).isEqualTo(HTTP_OK);
    readCookies(conn, cookies);
    conn.disconnect();
    return html;
  }

  /** Open a connection to the given URL. */
  protected HttpURLConnection openConnection(URI url) throws Exception {
    HttpURLConnection conn = (HttpURLConnection) url.toURL().openConnection();
    if (conn instanceof HttpsURLConnection) {
      getSslContext()
          .ifPresent(
              ctx -> ((HttpsURLConnection) conn).setSSLSocketFactory(ctx.getSocketFactory()));
      // disable hostname verification
      ((HttpsURLConnection) conn).setHostnameVerifier((hostname, session) -> true);
    }
    // must contain text/html
    conn.addRequestProperty("Accept", "text/html, *; q=.2, */*; q=.2");
    return conn;
  }

  protected static void postForm(
      HttpURLConnection conn, Map<String, String> data, Set<String> cookies) throws IOException {
    conn.setRequestMethod("POST");
    conn.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    writeCookies(conn, cookies);
    conn.setDoOutput(true);
    try (OutputStream out = conn.getOutputStream()) {
      for (Iterator<String> iterator = data.keySet().iterator(); iterator.hasNext(); ) {
        String name = iterator.next();
        String value = data.get(name);
        out.write(URLEncoder.encode(name, UTF_8).getBytes(UTF_8));
        out.write('=');
        out.write(URLEncoder.encode(value, UTF_8).getBytes(UTF_8));
        if (iterator.hasNext()) {
          out.write('&');
        }
      }
    }
  }

  protected static String readBody(HttpURLConnection conn) throws IOException {
    String html;
    try (InputStream is = conn.getInputStream()) {
      html =
          new BufferedReader(new InputStreamReader(is, UTF_8))
              .lines()
              .collect(Collectors.joining("\n"));
    }
    return html;
  }

  protected static URI readRedirectUrl(HttpURLConnection conn, Set<String> cookies)
      throws Exception {
    conn.setInstanceFollowRedirects(false);
    int responseCode = conn.getResponseCode();
    assertThat(responseCode).isIn(HTTP_MOVED_PERM, HTTP_MOVED_TEMP, HTTP_SEE_OTHER);
    String location = conn.getHeaderField("Location");
    assertThat(location).isNotNull();
    readCookies(conn, cookies);
    LOGGER.debug("Redirected to: {}", location);
    return URI.create(location);
  }

  protected static void readCookies(HttpURLConnection conn, Set<String> cookies) {
    List<String> cks = conn.getHeaderFields().get("Set-Cookie");
    if (cks != null) {
      cookies.addAll(cks);
    }
  }

  protected static void writeCookies(HttpURLConnection conn, Set<String> cookies) {
    for (String c : cookies) {
      conn.addRequestProperty("Cookie", c);
    }
  }
}

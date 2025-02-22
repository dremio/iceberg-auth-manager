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

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.collect.ImmutableMap;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractKeycloakUserEmulator extends InteractiveUserEmulator {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractKeycloakUserEmulator.class);

  private static final Pattern LOGIN_FORM_ACTION_PATTERN =
      Pattern.compile("<form.*action=\"([^\"]+)\".*>");

  public AbstractKeycloakUserEmulator(String agentName, String username, String password) {
    super(agentName, username, password);
  }

  @Override
  protected URI login(URI loginPageUrl, Set<String> cookies) throws Exception {
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
}

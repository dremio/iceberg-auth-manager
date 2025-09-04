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
package com.dremio.iceberg.authmgr.oauth2.config;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import io.smallrye.config.WithName;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for the <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.3">Resource Owner Password
 * Credentials Grant</a> flow.
 *
 * <p>Note: according to the <a
 * href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4">OAuth
 * 2.0 Security Best Current Practice, section 2.4</a> this flow should NOT be used anymore because
 * it "insecurely exposes the credentials of the resource owner to the client".
 */
public interface ResourceOwnerConfig {

  String GROUP_NAME = "resource-owner";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String USERNAME = "username";
  String PASSWORD = "password";

  /**
   * Username to use when authenticating against the OAuth2 server. Required if using OAuth2
   * authentication and {@link GrantType#PASSWORD} grant type, ignored otherwise.
   */
  @WithName(USERNAME)
  Optional<String> getUsername();

  /**
   * Password to use when authenticating against the OAuth2 server. Required if using OAuth2
   * authentication and the {@link GrantType#PASSWORD} grant type, ignored otherwise.
   */
  @WithName(PASSWORD)
  Optional<Secret> getPassword();

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getUsername().ifPresent(u -> properties.put(PREFIX + '.' + USERNAME, u));
    getPassword().ifPresent(p -> properties.put(PREFIX + '.' + PASSWORD, p.getValue()));
    return Map.copyOf(properties);
  }
}

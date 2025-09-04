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
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;

/**
 * Configuration properties for the <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Authorization Code Grant</a>
 * flow.
 *
 * <p>This flow is used to obtain an access token by redirecting the user to the OAuth2
 * authorization server, where they can log in and authorize the client application to access their
 * resources.
 */
public interface AuthorizationCodeConfig {

  String GROUP_NAME = "auth-code";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ENDPOINT = "endpoint";
  String REDIRECT_URI = "redirect-uri";
  String CALLBACK_BIND_HOST = "callback-bind-host";
  String CALLBACK_BIND_PORT = "callback-bind-port";
  String CALLBACK_CONTEXT_PATH = "callback-context-path";
  String PKCE_ENABLED = "pkce.enabled";
  String PKCE_METHOD = "pkce.method";

  /**
   * URL of the OAuth2 authorization endpoint. For Keycloak, this is typically {@code
   * https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth}.
   *
   * <p>If using the "authorization_code" grant type, either this property or {@link
   * BasicConfig#ISSUER_URL} must be set. In case it is not set, the authorization endpoint will be
   * discovered from the {@link BasicConfig#ISSUER_URL issuer URL}, using the OpenID Connect
   * Discovery metadata published by the issuer.
   */
  @WithName(ENDPOINT)
  Optional<URI> getAuthorizationEndpoint();

  /**
   * The redirect URI. This is the value of the {@code redirect_uri} parameter in the authorization
   * code request.
   *
   * <p>Optional; if not present, the URL will be computed from {@value #CALLBACK_BIND_HOST},
   * {@value #CALLBACK_BIND_PORT} and {@value #CALLBACK_CONTEXT_PATH}.
   *
   * <p>Specifying this value is generally only necessary in containerized environments, if a
   * reverse proxy modifies the callback before it reaches the client, or if external TLS
   * termination is performed.
   */
  @WithName(REDIRECT_URI)
  Optional<URI> getRedirectUri();

  /**
   * Address of the OAuth2 authorization code flow local web server.
   *
   * <p>The internal web server will listen for the authorization code callback on this address.
   * This is only used if the grant type to use is {@link GrantType#AUTHORIZATION_CODE}.
   *
   * <p>Optional; if not present, the server will listen on the loopback interface.
   */
  @WithName(CALLBACK_BIND_HOST)
  Optional<String> getCallbackBindHost();

  /**
   * Port of the OAuth2 authorization code flow local web server.
   *
   * <p>The internal web server will listen for the authorization code callback on this port. This
   * is only used if the grant type to use is {@link GrantType#AUTHORIZATION_CODE}.
   *
   * <p>Optional; if not present, a random port will be used.
   */
  @WithName(CALLBACK_BIND_PORT)
  OptionalInt getCallbackBindPort();

  /**
   * Context path of the OAuth2 authorization code flow local web server.
   *
   * <p>Optional; if not present, a default context path will be used.
   */
  @WithName(CALLBACK_CONTEXT_PATH)
  Optional<String> getCallbackContextPath();

  /**
   * Whether to enable PKCE (Proof Key for Code Exchange) for the authorization code flow. The
   * default is {@code true}.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</a>
   */
  @WithName(PKCE_ENABLED)
  @WithDefault("true")
  boolean isPkceEnabled();

  /**
   * The PKCE code challenge method to use. The default is {@code S256}. This is only used if PKCE
   * is enabled.
   *
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 Section 4.2</a>
   */
  @WithName(PKCE_METHOD)
  @WithDefault("S256")
  CodeChallengeMethod getCodeChallengeMethod();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getAuthorizationEndpoint().isPresent()) {
      validator.checkEndpoint(
          getAuthorizationEndpoint().get(),
          PREFIX + '.' + ENDPOINT,
          "authorization code flow: authorization endpoint");
    }
    if (getCallbackBindPort().isPresent()) {
      validator.check(
          getCallbackBindPort().getAsInt() >= 0 && getCallbackBindPort().getAsInt() <= 65535,
          PREFIX + '.' + CALLBACK_BIND_PORT,
          "authorization code flow: callback bind port must be between 0 and 65535 (inclusive)");
    }
    if (isPkceEnabled()) {
      validator.check(
          ConfigUtils.SUPPORTED_CODE_CHALLENGE_METHODS.contains(getCodeChallengeMethod()),
          PREFIX + '.' + PKCE_METHOD,
          "authorization code flow: code challenge method must be one of: %s",
          ConfigUtils.SUPPORTED_CODE_CHALLENGE_METHODS.stream()
              .map(CodeChallengeMethod::getValue)
              .collect(Collectors.joining("', '", "'", "'")));
    }
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getAuthorizationEndpoint()
        .ifPresent(u -> properties.put(PREFIX + '.' + ENDPOINT, u.toString()));
    getRedirectUri().ifPresent(u -> properties.put(PREFIX + '.' + REDIRECT_URI, u.toString()));
    getCallbackBindHost().ifPresent(h -> properties.put(PREFIX + '.' + CALLBACK_BIND_HOST, h));
    getCallbackBindPort()
        .ifPresent(p -> properties.put(PREFIX + '.' + CALLBACK_BIND_PORT, String.valueOf(p)));
    getCallbackContextPath()
        .ifPresent(p -> properties.put(PREFIX + '.' + CALLBACK_CONTEXT_PATH, p));
    properties.put(PREFIX + '.' + PKCE_ENABLED, String.valueOf(isPkceEnabled()));
    properties.put(PREFIX + '.' + PKCE_METHOD, getCodeChallengeMethod().getValue());
    return Map.copyOf(properties);
  }
}

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
import java.nio.file.Files;
import java.nio.file.Path;
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

  String CALLBACK_HTTPS = "callback.https";
  String CALLBACK_BIND_HOST = "callback.bind-host";
  String CALLBACK_BIND_PORT = "callback.bind-port";
  String CALLBACK_CONTEXT_PATH = "callback.context-path";

  String PKCE_ENABLED = "pkce.enabled";
  String PKCE_METHOD = "pkce.method";

  String SSL_KEYSTORE_PATH = "ssl.key-store.path";
  String SSL_KEYSTORE_PASSWORD = "ssl.key-store.password";
  String SSL_KEYSTORE_ALIAS = "ssl.key-store.alias";
  String SSL_PROTOCOLS = "ssl.protocols";
  String SSL_CIPHER_SUITES = "ssl.cipher-suites";

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
   * Whether to use HTTPS for the local web server that listens for the authorization code. The
   * default is {@code false}.
   *
   * <p>Ignored if {@value #REDIRECT_URI} is set.
   */
  @WithName(CALLBACK_HTTPS)
  @WithDefault("false")
  boolean isCallbackHttps();

  /**
   * Address of the OAuth2 authorization code flow local web server.
   *
   * <p>Ignored if {@value #REDIRECT_URI} is set.
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
   * <p>Ignored if {@value #REDIRECT_URI} is set.
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
   * <p>Ignored if {@value #REDIRECT_URI} is set.
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

  /**
   * Path to the key store to use for HTTPS requests. Optional, defaults to the system key store.
   *
   * <p>Ignored if {@value #CALLBACK_HTTPS} is {@code false} or if {@value #REDIRECT_URI} is set to
   * a non-HTTPS URL.
   */
  @WithName(SSL_KEYSTORE_PATH)
  Optional<Path> getSslKeyStorePath();

  /**
   * Password for the key store to use for HTTPS requests. Optional, defaults to no password.
   *
   * <p>Ignored if {@value #CALLBACK_HTTPS} is {@code false} or if {@value #REDIRECT_URI} is set to
   * a non-HTTPS URL.
   */
  @WithName(SSL_KEYSTORE_PASSWORD)
  Optional<String> getSslKeyStorePassword();

  /**
   * The alias of the key to use from the key store. Optional, defaults to the first matching key in
   * the store.
   *
   * <p>Ignored if {@value #CALLBACK_HTTPS} is {@code false} or if {@value #REDIRECT_URI} is set to
   * a non-HTTPS URL.
   */
  @WithName(SSL_KEYSTORE_ALIAS)
  Optional<String> getSslKeyStoreAlias();

  /**
   * A comma-separated list of SSL protocols to use for HTTPS requests. Optional, defaults to the
   * system protocols.
   *
   * <p>Ignored if {@value #CALLBACK_HTTPS} is {@code false} or if {@value #REDIRECT_URI} is set to
   * a non-HTTPS URL.
   */
  @WithName(SSL_PROTOCOLS)
  Optional<String> getSslProtocols();

  /**
   * A comma-separated list of SSL cipher suites to use for HTTPS requests. Optional, defaults to
   * the system cipher suites.
   *
   * <p>Ignored if {@value #CALLBACK_HTTPS} is {@code false} or if {@value #REDIRECT_URI} is set to
   * a non-HTTPS URL.
   */
  @WithName(SSL_CIPHER_SUITES)
  Optional<String> getSslCipherSuites();

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
    if (getSslKeyStorePath().isPresent()) {
      validator.check(
          Files.isReadable(getSslKeyStorePath().get()),
          PREFIX + '.' + SSL_KEYSTORE_PATH,
          "authorization code flow: SSL keystore path '%s' is not a file or is not readable",
          getSslKeyStorePath().get());
    }
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getAuthorizationEndpoint()
        .ifPresent(u -> properties.put(PREFIX + '.' + ENDPOINT, u.toString()));
    getRedirectUri().ifPresent(u -> properties.put(PREFIX + '.' + REDIRECT_URI, u.toString()));
    properties.put(PREFIX + '.' + CALLBACK_HTTPS, String.valueOf(isCallbackHttps()));
    getCallbackBindHost().ifPresent(h -> properties.put(PREFIX + '.' + CALLBACK_BIND_HOST, h));
    getCallbackBindPort()
        .ifPresent(p -> properties.put(PREFIX + '.' + CALLBACK_BIND_PORT, String.valueOf(p)));
    getCallbackContextPath()
        .ifPresent(p -> properties.put(PREFIX + '.' + CALLBACK_CONTEXT_PATH, p));
    properties.put(PREFIX + '.' + PKCE_ENABLED, String.valueOf(isPkceEnabled()));
    properties.put(PREFIX + '.' + PKCE_METHOD, getCodeChallengeMethod().getValue());
    getSslKeyStorePath()
        .ifPresent(p -> properties.put(PREFIX + '.' + SSL_KEYSTORE_PATH, p.toString()));
    getSslKeyStorePassword()
        .ifPresent(p -> properties.put(PREFIX + '.' + SSL_KEYSTORE_PASSWORD, p));
    getSslKeyStoreAlias().ifPresent(a -> properties.put(PREFIX + '.' + SSL_KEYSTORE_ALIAS, a));
    getSslProtocols().ifPresent(p -> properties.put(PREFIX + '.' + SSL_PROTOCOLS, p));
    getSslCipherSuites().ifPresent(c -> properties.put(PREFIX + '.' + SSL_CIPHER_SUITES, c));
    return Map.copyOf(properties);
  }
}

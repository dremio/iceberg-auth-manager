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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_BIND_HOST;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_BIND_PORT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.CALLBACK_CONTEXT_PATH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.PKCE_ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.PKCE_METHOD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode.REDIRECT_URI;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface AuthorizationCodeConfig {

  List<CodeChallengeMethod> SUPPORTED_CODE_CHALLENGE_METHODS =
      List.of(CodeChallengeMethod.PLAIN, CodeChallengeMethod.S256);

  AuthorizationCodeConfig DEFAULT = builder().build();

  /**
   * The OAuth2 authorization endpoint. Either this or {@link BasicConfig#getIssuerUrl()} must be
   * set, if the grant type is {@link GrantType#AUTHORIZATION_CODE}.
   *
   * @see OAuth2Properties.AuthorizationCode#ENDPOINT
   */
  Optional<URI> getAuthorizationEndpoint();

  /**
   * The redirect URI. This is the value of the {@code redirect_uri} parameter in the authorization
   * code request.
   *
   * <p>Optional; if not present, the URI will be computed from {@value
   * OAuth2Properties.AuthorizationCode#CALLBACK_BIND_HOST}, {@value
   * OAuth2Properties.AuthorizationCode#CALLBACK_BIND_PORT} and {@value
   * OAuth2Properties.AuthorizationCode#CALLBACK_CONTEXT_PATH}.
   *
   * <p>Specifying this value is generally only necessary in containerized environments, if a
   * reverse proxy modifies the callback before it reaches the client, or if external TLS
   * termination is performed.
   *
   * @see OAuth2Properties.AuthorizationCode#REDIRECT_URI
   */
  Optional<URI> getRedirectUri();

  /**
   * The address to use for the local web server that listens for the authorization code.
   *
   * @see OAuth2Properties.AuthorizationCode#CALLBACK_BIND_HOST
   */
  @Value.Default
  default String getCallbackBindHost() {
    return ConfigConstants.AUTHORIZATION_CODE_DEFAULT_CALLBACK_BIND_HOST;
  }

  /**
   * The port to use for the local web server that listens for the authorization code.
   *
   * <p>If not set or set to zero, a random port from the dynamic client port range will be used.
   * Only relevant when using the {@link GrantType#AUTHORIZATION_CODE} grant type.
   *
   * @see OAuth2Properties.AuthorizationCode#CALLBACK_BIND_PORT
   */
  OptionalInt getCallbackBindPort();

  /**
   * The context path to use for the local web server that listens for the authorization code.
   *
   * <p>If not set, a default context path will be used.
   *
   * @see OAuth2Properties.AuthorizationCode#CALLBACK_CONTEXT_PATH
   */
  Optional<String> getCallbackContextPath();

  /**
   * Whether to use PKCE (Proof Key for Code Exchange) for the authorization code flow. PKCE is
   * enabled by default.
   *
   * @see OAuth2Properties.AuthorizationCode#PKCE_ENABLED
   * @see <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</a>
   */
  @Value.Default
  default boolean isPkceEnabled() {
    return true;
  }

  /**
   * The transformation to use for the PKCE code verifier. Defaults to {@link
   * CodeChallengeMethod#S256}.
   *
   * @see OAuth2Properties.AuthorizationCode#PKCE_METHOD
   */
  @Value.Default
  default CodeChallengeMethod getCodeChallengeMethod() {
    return CodeChallengeMethod.S256;
  }

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getAuthorizationEndpoint().isPresent()) {
      validator.checkEndpoint(
          getAuthorizationEndpoint().get(),
          ENDPOINT,
          "authorization code flow: authorization endpoint %s");
    }
    if (getCallbackBindPort().isPresent()) {
      validator.check(
          getCallbackBindPort().getAsInt() >= 0 && getCallbackBindPort().getAsInt() <= 65535,
          CALLBACK_BIND_PORT,
          "authorization code flow: callback bind port must be between 0 and 65535 (inclusive)");
    }
    if (isPkceEnabled()) {
      validator.check(
          SUPPORTED_CODE_CHALLENGE_METHODS.contains(getCodeChallengeMethod()),
          PKCE_METHOD,
          "authorization code flow: code challenge method must be one of: %s",
          SUPPORTED_CODE_CHALLENGE_METHODS.stream()
              .map(CodeChallengeMethod::getValue)
              .collect(Collectors.joining("', '", "'", "'")));
    }
    validator.validate();
  }

  /**
   * Merges the given properties into this {@link AuthorizationCodeConfig} and returns the result.
   */
  default AuthorizationCodeConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    AuthorizationCodeConfig.Builder builder = builder();
    builder.endpointOption().set(properties, getAuthorizationEndpoint());
    builder.redirectUriOption().set(properties, getRedirectUri());
    builder.callbackBindHostOption().set(properties, getCallbackBindHost());
    builder
        .callbackBindPortOption()
        .set(properties, getCallbackBindPort().stream().boxed().findAny());
    builder.callbackContextPathOption().set(properties, getCallbackContextPath());
    builder.pkceEnabledOption().set(properties, isPkceEnabled());
    builder.codeChallengeMethodOption().set(properties, getCodeChallengeMethod());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableAuthorizationCodeConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(AuthorizationCodeConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      endpointOption().set(properties);
      redirectUriOption().set(properties);
      callbackBindHostOption().set(properties);
      callbackBindPortOption().set(properties);
      callbackContextPathOption().set(properties);
      pkceEnabledOption().set(properties);
      codeChallengeMethodOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder authorizationEndpoint(URI authorizationEndpoint);

    @CanIgnoreReturnValue
    Builder redirectUri(URI redirectUri);

    @CanIgnoreReturnValue
    Builder callbackBindHost(String callbackBindHost);

    @CanIgnoreReturnValue
    Builder callbackBindPort(int callbackBindPort);

    @CanIgnoreReturnValue
    Builder callbackContextPath(String callbackContextPath);

    @CanIgnoreReturnValue
    Builder pkceEnabled(boolean pkceEnabled);

    @CanIgnoreReturnValue
    Builder codeChallengeMethod(CodeChallengeMethod codeChallengeMethod);

    AuthorizationCodeConfig build();

    private ConfigOption<URI> endpointOption() {
      return ConfigOptions.simple(ENDPOINT, this::authorizationEndpoint, URI::create);
    }

    private ConfigOption<URI> redirectUriOption() {
      return ConfigOptions.simple(REDIRECT_URI, this::redirectUri, URI::create);
    }

    private ConfigOption<String> callbackBindHostOption() {
      return ConfigOptions.simple(CALLBACK_BIND_HOST, this::callbackBindHost);
    }

    private ConfigOption<Integer> callbackBindPortOption() {
      return ConfigOptions.simple(CALLBACK_BIND_PORT, this::callbackBindPort, Integer::parseInt);
    }

    private ConfigOption<String> callbackContextPathOption() {
      return ConfigOptions.simple(CALLBACK_CONTEXT_PATH, this::callbackContextPath);
    }

    private ConfigOption<Boolean> pkceEnabledOption() {
      return ConfigOptions.simple(PKCE_ENABLED, this::pkceEnabled, Boolean::parseBoolean);
    }

    private ConfigOption<CodeChallengeMethod> codeChallengeMethodOption() {
      return ConfigOptions.simple(
          PKCE_METHOD, this::codeChallengeMethod, CodeChallengeMethod::parse);
    }
  }
}

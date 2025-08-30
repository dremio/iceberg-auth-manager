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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_AUTH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_ID;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_SECRET;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.GRANT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN_ENDPOINT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface BasicConfig {

  List<GrantType> SUPPORTED_INITIAL_GRANT_TYPES =
      List.of(
          GrantType.CLIENT_CREDENTIALS,
          GrantType.PASSWORD,
          GrantType.AUTHORIZATION_CODE,
          GrantType.DEVICE_CODE,
          GrantType.TOKEN_EXCHANGE);

  List<ClientAuthenticationMethod> SUPPORTED_CLIENT_AUTH_METHODS =
      List.of(
          ClientAuthenticationMethod.NONE,
          ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
          ClientAuthenticationMethod.CLIENT_SECRET_POST,
          ClientAuthenticationMethod.CLIENT_SECRET_JWT,
          ClientAuthenticationMethod.PRIVATE_KEY_JWT);

  /**
   * The initial access token to use. Optional. If this is set, the agent will not attempt to fetch
   * the first new token from the Authorization server, but will use this token instead.
   *
   * <p>This option is mostly useful when migrating from the Iceberg OAuth2 manager to this OAuth2
   * manager. Always prefer letting the agent fetch an initial token from the configured
   * Authorization server.
   *
   * <p>When this option is set, the token is not validated by the agent, and it's not always
   * possible to refresh it. It's recommended to use this option only for testing purposes, or if
   * you know that the token is valid and will not expire too soon.
   *
   * @see OAuth2Properties.Basic#TOKEN
   */
  Optional<AccessToken> getToken();

  /**
   * The root URL of the Authorization server, which will be used for discovering supported
   * endpoints and their locations. For Keycloak, this is typically the realm URL: {@code
   * https://<keycloak-server>/realms/<realm-name>}.
   *
   * <p>Two "well-known" paths are supported for endpoint discovery: {@code
   * .well-known/openid-configuration} and {@code .well-known/oauth-authorization-server}. The full
   * metadata discovery URL will be constructed by appending these paths to the issuer URL.
   *
   * <p>Either this property or {@link #getTokenEndpoint()} must be set.
   *
   * @see <a
   *     href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
   *     Connect Discovery 1.0</a>
   * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414 Section 5</a>
   * @see OAuth2Properties.Basic#ISSUER_URL
   */
  Optional<URI> getIssuerUrl();

  /**
   * The OAuth2 token endpoint. Either this or {@link #getIssuerUrl()} must be set.
   *
   * <p>This URI may be relative, in which case it is assumed to be relative to the HTTP client's
   * base URI. In this case, the URI must not start with a slash.
   *
   * @see OAuth2Properties.Basic#TOKEN_ENDPOINT
   */
  Optional<URI> getTokenEndpoint();

  /**
   * The OAuth2 grant type. Defaults to {@link GrantType#CLIENT_CREDENTIALS}.
   *
   * @see OAuth2Properties.Basic#GRANT_TYPE
   */
  @Value.Default
  default GrantType getGrantType() {
    return GrantType.CLIENT_CREDENTIALS;
  }

  /**
   * The OAuth2 client ID. Must be set, unless a {@linkplain #getToken() static token} is provided.
   *
   * @see OAuth2Properties.Basic#CLIENT_ID
   */
  Optional<ClientID> getClientId();

  /**
   * The OAuth2 client authentication method. Defaults to {@link
   * ClientAuthenticationMethod#CLIENT_SECRET_BASIC}.
   *
   * @see OAuth2Properties.Basic#CLIENT_AUTH
   */
  @Value.Default
  default ClientAuthenticationMethod getClientAuthenticationMethod() {
    return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
  }

  /** Returns true if the client is a public client, i.e. it does not use client authentication. */
  @Value.Derived
  default boolean isPublicClient() {
    return getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE);
  }

  /**
   * The OAuth2 client secret. Must be set if the client is private (confidential) and client
   * authentication is done using a client secret.
   *
   * @see OAuth2Properties.Basic#CLIENT_SECRET
   */
  Optional<Secret> getClientSecret();

  /**
   * The OAuth2 {@link Scope}. Optional.
   *
   * @see OAuth2Properties.Basic#SCOPE
   */
  Optional<Scope> getScope();

  /**
   * Additional parameters to be included in the request. This is useful for custom parameters that
   * are not covered by the standard OAuth2.0 specification.
   *
   * @see OAuth2Properties.Basic#EXTRA_PARAMS_PREFIX
   */
  Map<String, String> getExtraRequestParameters();

  /**
   * Defines how long the agent should wait for tokens to be acquired. Defaults to {@link
   * OAuth2Properties.Basic#DEFAULT_TIMEOUT}.
   *
   * @see OAuth2Properties.Basic#TIMEOUT
   */
  @Value.Default
  default Duration getTimeout() {
    return ConfigConstants.DEFAULT_TIMEOUT;
  }

  /**
   * The minimum allowed value for {@link #getTimeout()}. Defaults to 30 seconds.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinTimeout() {
    return ConfigConstants.MIN_TIMEOUT;
  }

  @Value.Check
  default BasicConfig validate() {
    ConfigValidator validator = new ConfigValidator();
    BasicConfig basicConfig = this;
    validator.check(
        getIssuerUrl().isPresent() || getTokenEndpoint().isPresent(),
        List.of(ISSUER_URL, TOKEN_ENDPOINT),
        "either issuer URL or token endpoint must be set");
    if (getIssuerUrl().isPresent()) {
      validator.checkEndpoint(getIssuerUrl().get(), ISSUER_URL, "Issuer URL");
    }
    if (getTokenEndpoint().isPresent()) {
      validator.checkEndpoint(getTokenEndpoint().get(), TOKEN_ENDPOINT, "Token endpoint");
    }
    validator.check(
        SUPPORTED_INITIAL_GRANT_TYPES.contains(getGrantType()),
        GRANT_TYPE,
        "grant type must be one of: %s",
        SUPPORTED_INITIAL_GRANT_TYPES.stream()
            .map(GrantType::getValue)
            .collect(Collectors.joining("', '", "'", "'")));
    validator.check(
        SUPPORTED_CLIENT_AUTH_METHODS.contains(getClientAuthenticationMethod()),
        CLIENT_AUTH,
        "client authentication method must be one of: %s",
        SUPPORTED_CLIENT_AUTH_METHODS.stream()
            .map(ClientAuthenticationMethod::getValue)
            .collect(Collectors.joining("', '", "'", "'")));
    // Only validate client ID and client secret if a token is not provided
    if (getToken().isEmpty()) {
      validator.check(getClientId().isPresent(), CLIENT_ID, "client ID must not be empty");
      if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
        validator.check(
            getClientSecret().isPresent(),
            List.of(CLIENT_AUTH, CLIENT_SECRET),
            "client secret must not be empty when client authentication is '%s'",
            getClientAuthenticationMethod().getValue());
      } else if (getClientAuthenticationMethod()
          .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
        validator.check(
            getClientSecret().isEmpty(),
            List.of(CLIENT_AUTH, CLIENT_SECRET),
            "client secret must not be set when client authentication is '%s'",
            getClientAuthenticationMethod().getValue());
      } else if (getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
        validator.check(
            getClientSecret().isEmpty(),
            List.of(CLIENT_AUTH, CLIENT_SECRET),
            "client secret must not be set when client authentication is '%s'",
            ClientAuthenticationMethod.NONE.getValue());
        validator.check(
            !getGrantType().equals(GrantType.CLIENT_CREDENTIALS),
            List.of(CLIENT_AUTH, GRANT_TYPE),
            "grant type must not be '%s' when client authentication is '%s'",
            GrantType.CLIENT_CREDENTIALS.getValue(),
            ClientAuthenticationMethod.NONE.getValue());
      }
    }
    validator.check(
        getTimeout().compareTo(getMinTimeout()) >= 0,
        TIMEOUT,
        "timeout must be greater than or equal to %s",
        getMinTimeout());
    validator.validate();
    return basicConfig;
  }

  /** Merges the given properties into this {@link BasicConfig} and returns the result. */
  default BasicConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    BasicConfig.Builder builder = builder();
    builder.tokenOption().set(properties, getToken());
    builder.clientIdOption().set(properties, getClientId());
    builder.clientAuthenticationOption().set(properties, getClientAuthenticationMethod());
    builder.clientSecretOption().set(properties, getClientSecret());
    builder.issuerUrlOption().set(properties, getIssuerUrl());
    builder.tokenEndpointOption().set(properties, getTokenEndpoint());
    builder.grantTypeOption().set(properties, getGrantType());
    builder.scopeOption().set(properties, getScope());
    builder.extraRequestParametersOption().set(properties, getExtraRequestParameters());
    builder.timeoutOption().set(properties, getTimeout());
    builder.minTimeout(getMinTimeout());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableBasicConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(BasicConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      tokenOption().set(properties);
      clientIdOption().set(properties);
      clientAuthenticationOption().set(properties);
      clientSecretOption().set(properties);
      issuerUrlOption().set(properties);
      tokenEndpointOption().set(properties);
      grantTypeOption().set(properties);
      scopeOption().set(properties);
      extraRequestParametersOption().set(properties);
      timeoutOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder token(AccessToken token);

    @CanIgnoreReturnValue
    Builder issuerUrl(URI issuerUrl);

    @CanIgnoreReturnValue
    Builder tokenEndpoint(URI tokenEndpoint);

    @CanIgnoreReturnValue
    Builder grantType(GrantType grantType);

    @CanIgnoreReturnValue
    Builder clientId(ClientID clientId);

    @CanIgnoreReturnValue
    Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod);

    @CanIgnoreReturnValue
    Builder clientSecret(Secret clientSecret);

    @CanIgnoreReturnValue
    Builder scope(Scope scope);

    @CanIgnoreReturnValue
    Builder extraRequestParameters(Map<String, ? extends String> extraRequestParameters);

    @CanIgnoreReturnValue
    Builder timeout(Duration timeout);

    @CanIgnoreReturnValue
    Builder minTimeout(Duration minTimeout);

    BasicConfig build();

    private ConfigOption<AccessToken> tokenOption() {
      return ConfigOptions.simple(TOKEN, this::token, BearerAccessToken::new);
    }

    private ConfigOption<ClientID> clientIdOption() {
      return ConfigOptions.simple(CLIENT_ID, this::clientId, ClientID::new);
    }

    private ConfigOption<ClientAuthenticationMethod> clientAuthenticationOption() {
      return ConfigOptions.simple(
          CLIENT_AUTH, this::clientAuthenticationMethod, ClientAuthenticationMethod::parse);
    }

    private ConfigOption<Secret> clientSecretOption() {
      return ConfigOptions.simple(CLIENT_SECRET, this::clientSecret, Secret::new);
    }

    private ConfigOption<URI> issuerUrlOption() {
      return ConfigOptions.simple(ISSUER_URL, this::issuerUrl, URI::create);
    }

    private ConfigOption<URI> tokenEndpointOption() {
      return ConfigOptions.simple(TOKEN_ENDPOINT, this::tokenEndpoint, URI::create);
    }

    private ConfigOption<GrantType> grantTypeOption() {
      return ConfigOptions.simple(GRANT_TYPE, this::grantType, ConfigUtils::parseGrantType);
    }

    private ConfigOption<Scope> scopeOption() {
      return ConfigOptions.simple(SCOPE, this::scope, Scope::parse);
    }

    private ConfigOption<Map<String, String>> extraRequestParametersOption() {
      return ConfigOptions.prefixMap(EXTRA_PARAMS_PREFIX, this::extraRequestParameters);
    }

    private ConfigOption<Duration> timeoutOption() {
      return ConfigOptions.simple(TIMEOUT, this::timeout, Duration::parse);
    }
  }
}

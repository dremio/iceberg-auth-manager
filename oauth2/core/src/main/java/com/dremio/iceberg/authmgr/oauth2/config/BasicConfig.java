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
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.DIALECT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.GRANT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.TOKEN_ENDPOINT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.iceberg.rest.ResourcePaths;
import org.immutables.value.Value;
import org.slf4j.LoggerFactory;

@AuthManagerImmutable
public interface BasicConfig {

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
   * The OAuth2 client ID. Must be set, unless {@link #getDialect()} is {@link
   * Dialect#ICEBERG_REST}.
   *
   * @see OAuth2Properties.Basic#CLIENT_ID
   */
  Optional<String> getClientId();

  /**
   * The OAuth2 client authentication method. Defaults to {@link
   * ClientAuthentication#CLIENT_SECRET_BASIC} if the client is private, or {@link
   * ClientAuthentication#NONE} if the client is public.
   *
   * <p>Ignored when dialect is {@link Dialect#ICEBERG_REST} or when a {@linkplain #getToken()
   * token} is provided.
   *
   * @see OAuth2Properties.Basic#CLIENT_AUTH
   */
  @Value.Default
  default ClientAuthentication getClientAuthentication() {
    return getClientSecret().isPresent()
        ? ClientAuthentication.CLIENT_SECRET_BASIC
        : ClientAuthentication.NONE;
  }

  /**
   * The OAuth2 client secret. Must be set if the client is private (confidential) and client
   * authentication is done using a client secret.
   *
   * @see OAuth2Properties.Basic#CLIENT_SECRET
   */
  Optional<Secret> getClientSecret();

  /**
   * The OAuth2 scopes. Optional.
   *
   * @see OAuth2Properties.Basic#SCOPE
   */
  List<String> getScopes();

  /**
   * Additional parameters to be included in the request. This is useful for custom parameters that
   * are not covered by the standard OAuth2.0 specification.
   *
   * @see OAuth2Properties.Basic#EXTRA_PARAMS_PREFIX
   */
  Map<String, String> getExtraRequestParameters();

  /**
   * The OAuth2 dialect. Possible values are: {@link Dialect#STANDARD} and {@link
   * Dialect#ICEBERG_REST}.
   *
   * <p>If the Iceberg dialect is selected, the agent will behave exactly like the built-in OAuth2
   * manager from Iceberg Core. This dialect should only be selected if the token endpoint is
   * internal to the REST catalog server, and the server is configured to understand this dialect.
   *
   * <p>The Iceberg dialect's main differences from standard OAuth2 are:
   *
   * <ul>
   *   <li>Only {@link GrantType#CLIENT_CREDENTIALS} grant type is supported;
   *   <li>Token refreshes are done with the {@link GrantType#TOKEN_EXCHANGE} grant type;
   *   <li>Token refreshes are done with Bearer authentication, not Basic authentication;
   *   <li>Public clients are not supported, however client secrets without client IDs are
   *       supported;
   *   <li>Client ID and client secret are sent as request body parameters, and not as Basic
   *       authentication.
   * </ul>
   *
   * Optional. The default value tries to guess the dialect based on the current configuration.
   *
   * @see OAuth2Properties.Basic#DIALECT
   */
  @Value.Default
  default Dialect getDialect() {
    if (getToken().isPresent()) {
      return Dialect.ICEBERG_REST;
    }
    if (getClientSecret().isPresent() && getClientId().isEmpty()) {
      // Only Iceberg dialect supports this configuration
      return Dialect.ICEBERG_REST;
    }
    return getTokenEndpoint()
        .filter(uri -> !uri.isAbsolute())
        .map(uri -> Dialect.ICEBERG_REST)
        .orElse(Dialect.STANDARD);
  }

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
    if (getDialect() == Dialect.STANDARD) {
      validator.check(
          getIssuerUrl().isPresent() || getTokenEndpoint().isPresent(),
          List.of(ISSUER_URL, TOKEN_ENDPOINT),
          "either issuer URL or token endpoint must be set");
    } else if (getIssuerUrl().isEmpty() && getTokenEndpoint().isEmpty()) {
      LoggerFactory.getLogger(BasicConfig.class)
          .warn(
              "The selected dialect is {} and the configuration does not specify a token endpoint nor an issuer URL: "
                  + "inferring that the token endpoint is internal to the REST catalog server. "
                  + "This automatic inference will be removed in a future release. "
                  + "Please define one of the following properties: '{}' or '{}'.",
              Dialect.ICEBERG_REST,
              ISSUER_URL,
              TOKEN_ENDPOINT);
      basicConfig =
          BasicConfig.builder()
              .from(basicConfig)
              .tokenEndpoint(URI.create(ResourcePaths.tokens()))
              .build();
    }

    if (getIssuerUrl().isPresent()) {
      validator.checkEndpoint(getIssuerUrl().get(), true, ISSUER_URL, "Issuer URL %s");
    }
    if (getTokenEndpoint().isPresent()) {
      // The token endpoint is allowed to be relative, in which case we assume
      // it is relative to the HTTP client's base URI and points to the REST catalog
      // server's internal token endpoint.
      validator.checkEndpoint(getTokenEndpoint().get(), false, TOKEN_ENDPOINT, "Token endpoint %s");
    }
    validator.check(
        getGrantType().isInitial(),
        GRANT_TYPE,
        "grant type must be one of: %s",
        Arrays.stream(GrantType.values())
            .filter(GrantType::isInitial)
            .map(GrantType::name)
            .map(String::toLowerCase)
            .collect(Collectors.joining("', '", "'", "'")));
    if (getDialect() == Dialect.ICEBERG_REST) {
      validator.check(
          getGrantType() == GrantType.CLIENT_CREDENTIALS,
          List.of(GRANT_TYPE, DIALECT),
          "Iceberg OAuth2 dialect only supports the '%s' grant type",
          GrantType.CLIENT_CREDENTIALS.getCommonName());
    }
    // Only validate client ID and client secret if a token is not provided
    if (getToken().isEmpty()) {
      if (getDialect() == Dialect.ICEBERG_REST) {
        validator.check(
            getClientSecret().isPresent(),
            List.of(CLIENT_SECRET, DIALECT),
            "client secret must not be empty when Iceberg OAuth2 dialect is used");
      } else {
        validator.check(
            getClientId().isPresent() && !getClientId().get().isEmpty(),
            CLIENT_ID,
            "client ID must not be empty");
        if (getClientAuthentication().isClientSecret()) {
          validator.check(
              getClientSecret().isPresent(),
              List.of(CLIENT_AUTH, CLIENT_SECRET),
              "client secret must not be empty when client authentication is '%s'",
              getClientAuthentication().getCanonicalName());
        } else {
          validator.check(
              getClientSecret().isPresent() || getGrantType() != GrantType.CLIENT_CREDENTIALS,
              List.of(GRANT_TYPE, CLIENT_SECRET),
              "client secret must not be empty when grant type is '%s'",
              GrantType.CLIENT_CREDENTIALS.getCommonName());
        }
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
    builder.clientAuthenticationOption().set(properties, getClientAuthentication());
    builder.clientSecretOption().set(properties, getClientSecret());
    builder.issuerUrlOption().set(properties, getIssuerUrl());
    builder.tokenEndpointOption().set(properties, getTokenEndpoint());
    builder.grantTypeOption().set(properties, getGrantType());
    builder.scopesOption().set(properties, getScopes());
    builder.dialectOption().set(properties, getDialect());
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
      scopesOption().set(properties);
      dialectOption().set(properties);
      extraRequestParametersOption().set(properties);
      timeoutOption().set(properties);
      return this;
    }

    @CanIgnoreReturnValue
    default Builder token(String token) {
      return token(AccessToken.of(token));
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
    Builder clientId(String clientId);

    @CanIgnoreReturnValue
    Builder clientAuthentication(ClientAuthentication clientAuthentication);

    @CanIgnoreReturnValue
    default Builder clientSecret(String clientSecret) {
      return clientSecret(Secret.of(clientSecret));
    }

    @CanIgnoreReturnValue
    Builder clientSecret(Secret clientSecret);

    @CanIgnoreReturnValue
    Builder scopes(Iterable<String> scopes);

    @CanIgnoreReturnValue
    Builder extraRequestParameters(Map<String, ? extends String> extraRequestParameters);

    @CanIgnoreReturnValue
    Builder dialect(Dialect dialect);

    @CanIgnoreReturnValue
    Builder timeout(Duration timeout);

    @CanIgnoreReturnValue
    Builder minTimeout(Duration minTimeout);

    BasicConfig build();

    private ConfigOption<AccessToken> tokenOption() {
      return ConfigOptions.simple(TOKEN, this::token, AccessToken::of);
    }

    private ConfigOption<String> clientIdOption() {
      return ConfigOptions.simple(CLIENT_ID, this::clientId);
    }

    private ConfigOption<ClientAuthentication> clientAuthenticationOption() {
      return ConfigOptions.simple(
          CLIENT_AUTH, this::clientAuthentication, ClientAuthentication::fromConfigName);
    }

    private ConfigOption<Secret> clientSecretOption() {
      return ConfigOptions.simple(CLIENT_SECRET, this::clientSecret, Secret::of);
    }

    private ConfigOption<URI> issuerUrlOption() {
      return ConfigOptions.simple(ISSUER_URL, this::issuerUrl, URI::create);
    }

    private ConfigOption<URI> tokenEndpointOption() {
      return ConfigOptions.simple(TOKEN_ENDPOINT, this::tokenEndpoint, URI::create);
    }

    private ConfigOption<GrantType> grantTypeOption() {
      return ConfigOptions.simple(GRANT_TYPE, this::grantType, GrantType::fromConfigName);
    }

    private ConfigOption<List<String>> scopesOption() {
      return ConfigOptions.simple(SCOPE, this::scopes, ConfigUtils::scopesAsList);
    }

    private ConfigOption<Dialect> dialectOption() {
      return ConfigOptions.simple(DIALECT, this::dialect, Dialect::fromConfigName);
    }

    private ConfigOption<Map<String, String>> extraRequestParametersOption() {
      return ConfigOptions.prefixMap(EXTRA_PARAMS_PREFIX, this::extraRequestParameters);
    }

    private ConfigOption<Duration> timeoutOption() {
      return ConfigOptions.simple(TIMEOUT, this::timeout, Duration::parse);
    }
  }
}

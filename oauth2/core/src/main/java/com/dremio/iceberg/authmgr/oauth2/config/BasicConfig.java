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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Basic OAuth2 properties. These properties are used to configure the basic OAuth2 options such as
 * the issuer URL, token endpoint, client ID, and client secret.
 */
public interface BasicConfig {

  String PREFIX = OAuth2Config.PREFIX;

  String TOKEN = "token";
  String ISSUER_URL = "issuer-url";
  String TOKEN_ENDPOINT = "token-endpoint";
  String GRANT_TYPE = "grant-type";
  String CLIENT_ID = "client-id";
  String CLIENT_AUTH = "client-auth";
  String CLIENT_SECRET = "client-secret";
  String SCOPE = "scope";
  String EXTRA_PARAMS = "extra-params";
  String TIMEOUT = "timeout";

  String DEFAULT_TIMEOUT = "PT5M";

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
   */
  @WithName(TOKEN)
  Optional<TypelessAccessToken> getToken();

  /**
   * OAuth2 issuer URL.
   *
   * <p>The root URL of the Authorization server, which will be used for discovering supported
   * endpoints and their locations. For Keycloak, this is typically the realm URL: {@code
   * https://<keycloak-server>/realms/<realm-name>}.
   *
   * <p>Two "well-known" paths are supported for endpoint discovery: {@code
   * .well-known/openid-configuration} and {@code .well-known/oauth-authorization-server}. The full
   * metadata discovery URL will be constructed by appending these paths to the issuer URL.
   *
   * <p>Either this property or {@link #TOKEN_ENDPOINT} must be set.
   *
   * @see <a
   *     href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
   *     Connect Discovery 1.0</a>
   * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414 Section 5</a>
   */
  @WithName(ISSUER_URL)
  Optional<URI> getIssuerUrl();

  /**
   * URL of the OAuth2 token endpoint. For Keycloak, this is typically {@code
   * https://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/token}.
   *
   * <p>Either this property or {@link #ISSUER_URL} must be set. In case it is not set, the token
   * endpoint will be discovered from the {@link #ISSUER_URL issuer URL}, using the OpenID Connect
   * Discovery metadata published by the issuer.
   */
  @WithName(TOKEN_ENDPOINT)
  Optional<URI> getTokenEndpoint();

  /**
   * The grant type to use when authenticating against the OAuth2 server. Valid values are:
   *
   * <ul>
   *   <li>{@link GrantType#CLIENT_CREDENTIALS client_credentials}
   *   <li>{@link GrantType#PASSWORD password}
   *   <li>{@link GrantType#AUTHORIZATION_CODE authorization_code}
   *   <li>{@link GrantType#DEVICE_CODE urn:ietf:params:oauth:grant-type:device_code}
   *   <li>{@link GrantType#TOKEN_EXCHANGE urn:ietf:params:oauth:grant-type:token-exchange}
   * </ul>
   *
   * Optional, defaults to {@code client_credentials}.
   */
  @WithName(GRANT_TYPE)
  @WithDefault("client_credentials")
  GrantType getGrantType();

  /**
   * Client ID to use when authenticating against the OAuth2 server. Required, unless a {@linkplain
   * #TOKEN static token} is provided.
   */
  @WithName(CLIENT_ID)
  Optional<ClientID> getClientId();

  /**
   * The OAuth2 client authentication method to use. Valid values are:
   *
   * <ul>
   *   <li>{@link ClientAuthenticationMethod#NONE none}: the client does not authenticate itself at
   *       the token endpoint, because it is a public client with no client secret or other
   *       authentication mechanism.
   *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_BASIC client_secret_basic}: client secret
   *       is sent in the HTTP Basic Authorization header.
   *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_POST client_secret_post}: client secret
   *       is sent in the request body as a form parameter.
   *   <li>{@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}: client secret is
   *       used to sign a JWT token.
   *   <li>{@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt}: client authenticates
   *       with a JWT assertion signed with a private key.
   * </ul>
   *
   * The default is {@code client_secret_basic}.
   */
  @WithName(CLIENT_AUTH)
  @WithDefault("client_secret_basic")
  ClientAuthenticationMethod getClientAuthenticationMethod();

  /**
   * Client secret to use when authenticating against the OAuth2 server. Required if the client is
   * private and is authenticated using the standard "client-secret" methods. If other
   * authentication methods are used (e.g. {@code private_key_jwt}), this property is ignored.
   */
  @WithName(CLIENT_SECRET)
  Optional<Secret> getClientSecret();

  /**
   * Space-separated list of scopes to include in each request to the OAuth2 server. Optional,
   * defaults to empty (no scopes).
   *
   * <p>The scope names will not be validated by the OAuth2 agent; make sure they are valid
   * according to <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">RFC 6749
   * Section 3.3</a>.
   */
  @WithName(SCOPE)
  Optional<Scope> getScope();

  /**
   * Extra parameters to include in each request to the token and device authorization endpoints.
   * This is useful for custom parameters that are not covered by the standard OAuth2.0
   * specification. Optional, defaults to empty.
   *
   * <p>This is a prefix property, and multiple values can be set, each with a different key and
   * value. The values must NOT be URL-encoded. Example:
   *
   * <pre>{@code
   * rest.auth.oauth2.extra-params.custom_param1=custom_value1"
   * rest.auth.oauth2.extra-params.custom_param2=custom_value2"
   * }</pre>
   *
   * For example, Auth0 requires the {@code audience} parameter to be set to the API identifier.
   * This can be done by setting the following configuration:
   *
   * <pre>{@code
   * rest.auth.oauth2.extra-params.audience=https://iceberg-rest-catalog/api
   * }</pre>
   */
  @WithName(EXTRA_PARAMS)
  Map<String, String> getExtraRequestParameters();

  /**
   * Defines how long the agent should wait for tokens to be acquired. Optional, defaults to {@value
   * #DEFAULT_TIMEOUT}.
   */
  @WithName(TIMEOUT)
  @WithDefault(DEFAULT_TIMEOUT)
  Duration getTimeout();

  /**
   * The minimum allowed value for {@link #getTimeout()}. Defaults to 30 seconds.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("min-timeout")
  @WithDefault("PT30S")
  Duration getMinTimeout();

  default BasicConfig validate() {
    ConfigValidator validator = new ConfigValidator();
    BasicConfig basicConfig = this;
    validator.check(
        getIssuerUrl().isPresent() || getTokenEndpoint().isPresent(),
        List.of(PREFIX + '.' + ISSUER_URL, PREFIX + '.' + TOKEN_ENDPOINT),
        "either issuer URL or token endpoint must be set");
    if (getIssuerUrl().isPresent()) {
      validator.checkEndpoint(getIssuerUrl().get(), PREFIX + '.' + ISSUER_URL, "Issuer URL");
    }
    if (getTokenEndpoint().isPresent()) {
      validator.checkEndpoint(
          getTokenEndpoint().get(), PREFIX + '.' + TOKEN_ENDPOINT, "Token endpoint");
    }
    validator.check(
        ConfigUtils.SUPPORTED_INITIAL_GRANT_TYPES.contains(getGrantType()),
        PREFIX + '.' + GRANT_TYPE,
        "grant type must be one of: %s",
        ConfigUtils.SUPPORTED_INITIAL_GRANT_TYPES.stream()
            .map(GrantType::getValue)
            .collect(Collectors.joining("', '", "'", "'")));
    validator.check(
        ConfigUtils.SUPPORTED_CLIENT_AUTH_METHODS.contains(getClientAuthenticationMethod()),
        PREFIX + '.' + CLIENT_AUTH,
        "client authentication method must be one of: %s",
        ConfigUtils.SUPPORTED_CLIENT_AUTH_METHODS.stream()
            .map(ClientAuthenticationMethod::getValue)
            .collect(Collectors.joining("', '", "'", "'")));
    // Only validate client ID and client secret if a token is not provided
    if (getToken().isEmpty()) {
      validator.check(
          getClientId().isPresent(), PREFIX + '.' + CLIENT_ID, "client ID must not be empty");
      if (ConfigUtils.requiresClientSecret(getClientAuthenticationMethod())) {
        validator.check(
            getClientSecret().isPresent(),
            List.of(PREFIX + '.' + CLIENT_AUTH, PREFIX + '.' + CLIENT_SECRET),
            "client secret must not be empty when client authentication is '%s'",
            getClientAuthenticationMethod().getValue());
      } else if (getClientAuthenticationMethod()
          .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
        validator.check(
            getClientSecret().isEmpty(),
            List.of(PREFIX + '.' + CLIENT_AUTH, PREFIX + '.' + CLIENT_SECRET),
            "client secret must not be set when client authentication is '%s'",
            getClientAuthenticationMethod().getValue());
      } else if (getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
        validator.check(
            getClientSecret().isEmpty(),
            List.of(PREFIX + '.' + CLIENT_AUTH, PREFIX + '.' + CLIENT_SECRET),
            "client secret must not be set when client authentication is '%s'",
            ClientAuthenticationMethod.NONE.getValue());
        validator.check(
            !getGrantType().equals(GrantType.CLIENT_CREDENTIALS),
            List.of(PREFIX + '.' + CLIENT_AUTH, PREFIX + '.' + GRANT_TYPE),
            "grant type must not be '%s' when client authentication is '%s'",
            GrantType.CLIENT_CREDENTIALS.getValue(),
            ClientAuthenticationMethod.NONE.getValue());
      }
    }
    validator.check(
        getTimeout().compareTo(getMinTimeout()) >= 0,
        PREFIX + '.' + TIMEOUT,
        "timeout must be greater than or equal to %s",
        getMinTimeout());
    validator.validate();
    return basicConfig;
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getToken().ifPresent(t -> properties.put(PREFIX + '.' + "token", t.getValue()));
    getIssuerUrl().ifPresent(u -> properties.put(PREFIX + '.' + ISSUER_URL, u.toString()));
    getTokenEndpoint().ifPresent(u -> properties.put(PREFIX + '.' + TOKEN_ENDPOINT, u.toString()));
    properties.put(PREFIX + '.' + GRANT_TYPE, getGrantType().getValue());
    properties.put(PREFIX + '.' + CLIENT_AUTH, getClientAuthenticationMethod().getValue());
    getClientId().ifPresent(i -> properties.put(PREFIX + '.' + CLIENT_ID, i.getValue()));
    getClientSecret().ifPresent(s -> properties.put(PREFIX + '.' + CLIENT_SECRET, s.getValue()));
    getScope().ifPresent(s -> properties.put(PREFIX + '.' + SCOPE, s.toString()));
    getExtraRequestParameters()
        .forEach((k, v) -> properties.put(PREFIX + '.' + EXTRA_PARAMS + '.' + k, v));
    properties.put(PREFIX + '.' + TIMEOUT, getTimeout().toString());
    properties.put(PREFIX + '.' + "min-timeout", getMinTimeout().toString());
    return Map.copyOf(properties);
  }
}

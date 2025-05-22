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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_AUTH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_ID;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_SECRET;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.TOKEN_ENDPOINT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthentication;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.immutables.value.Value;

/** Configuration for OAuth2 impersonation. */
@AuthManagerImmutable
public interface ImpersonationConfig {

  ImpersonationConfig DEFAULT = builder().build();

  /**
   * Whether "impersonation" is enabled. If enabled, the access token obtained from the OAuth2
   * server with the configured initial grant will be exchanged for a new token, using the token
   * exchange grant type.
   *
   * @see OAuth2Properties.Impersonation#ENABLED
   */
  @Value.Default
  default boolean isEnabled() {
    return false;
  }

  /**
   * The root URL of the impersonation Authorization server, which will be used for discovering
   * supported endpoints and their locations. For Keycloak, this is typically the realm URL: {@code
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
   * @see OAuth2Properties.Impersonation#ISSUER_URL
   */
  Optional<URI> getIssuerUrl();

  /**
   * The OAuth2 token endpoint to use for impersonations only. Either this or {@link
   * #getIssuerUrl()} must be set.
   *
   * @see OAuth2Properties.Impersonation#TOKEN_ENDPOINT
   */
  Optional<URI> getTokenEndpoint();

  /**
   * The OAuth2 client ID to use for impersonations only.
   *
   * @see OAuth2Properties.Impersonation#CLIENT_ID
   */
  Optional<String> getClientId();

  /**
   * The OAUth2 client authentication method for impersonations only. Defaults to {@link
   * ClientAuthentication#CLIENT_SECRET_BASIC} if the client is private, or {@link
   * ClientAuthentication#NONE} if the client is public.
   *
   * @see OAuth2Properties.Impersonation#CLIENT_AUTH
   */
  @Value.Default
  default ClientAuthentication getClientAuthentication() {
    return getClientSecret().isPresent()
        ? ClientAuthentication.CLIENT_SECRET_BASIC
        : ClientAuthentication.NONE;
  }

  /**
   * The OAuth2 client secret for impersonations only. Must be set if the client is private
   * (confidential) and client authentication is done using a client secret.
   *
   * @see OAuth2Properties.Impersonation#CLIENT_SECRET
   */
  Optional<Secret> getClientSecret();

  /**
   * The OAuth2 scopes for impersonation only. Optional.
   *
   * @see OAuth2Properties.Impersonation#SCOPE
   */
  List<String> getScopes();

  /**
   * Additional parameters to be included in the request for impersonation only. This is useful for
   * custom parameters that are not covered by the standard OAuth2.0 specification.
   *
   * @see OAuth2Properties.Impersonation#EXTRA_PARAMS_PREFIX
   */
  Map<String, String> getExtraRequestParameters();

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (isEnabled()) {
      validator.check(
          getClientId().isPresent(),
          CLIENT_ID,
          "impersonation client ID must be present when impersonation is enabled");
      validator.check(
          getIssuerUrl().isPresent() || getTokenEndpoint().isPresent(),
          List.of(ISSUER_URL, TOKEN_ENDPOINT),
          "either impersonation issuer URL or impersonation token endpoint must be set");
      if (getClientAuthentication().isClientSecret()) {
        validator.check(
            getClientSecret().isPresent(),
            List.of(CLIENT_AUTH, CLIENT_SECRET),
            "client secret must not be empty when client authentication is '%s'",
            getClientAuthentication().getCanonicalName());
      }
    }
    if (getClientId().isPresent()) {
      validator.check(
          !getClientId().get().isEmpty(), CLIENT_ID, "impersonation client ID must not be empty");
    }
    if (getIssuerUrl().isPresent()) {
      validator.checkEndpoint(
          getIssuerUrl().get(), true, ISSUER_URL, "impersonation issuer URL %s");
    }
    if (getTokenEndpoint().isPresent()) {
      validator.checkEndpoint(
          getTokenEndpoint().get(), true, TOKEN_ENDPOINT, "impersonation token endpoint %s");
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link ImpersonationConfig} and returns the result. */
  default ImpersonationConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    Builder builder = builder();
    builder.enabledOption().merge(properties, isEnabled());
    builder.clientIdOption().merge(properties, getClientId());
    builder.clientAuthenticationOption().merge(properties, getClientAuthentication());
    builder.clientSecretOption().merge(properties, getClientSecret());
    builder.issuerUrlOption().merge(properties, getIssuerUrl());
    builder.tokenEndpointOption().merge(properties, getTokenEndpoint());
    builder.scopesOption().merge(properties, getScopes());
    builder.extraRequestParametersOption().merge(properties, getExtraRequestParameters());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableImpersonationConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(ImpersonationConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      enabledOption().apply(properties);
      clientIdOption().apply(properties);
      clientAuthenticationOption().apply(properties);
      clientSecretOption().apply(properties);
      issuerUrlOption().apply(properties);
      tokenEndpointOption().apply(properties);
      scopesOption().apply(properties);
      extraRequestParametersOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder enabled(boolean enabled);

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
    Builder issuerUrl(URI issuerUrl);

    @CanIgnoreReturnValue
    Builder tokenEndpoint(URI tokenEndpoint);

    @CanIgnoreReturnValue
    Builder scopes(Iterable<String> scopes);

    @CanIgnoreReturnValue
    Builder extraRequestParameters(Map<String, ? extends String> extraRequestParameters);

    ImpersonationConfig build();

    private ConfigOption<Boolean> enabledOption() {
      return ConfigOptions.of(ENABLED, this::enabled, Boolean::parseBoolean);
    }

    private ConfigOption<String> clientIdOption() {
      return ConfigOptions.of(CLIENT_ID, this::clientId);
    }

    private ConfigOption<ClientAuthentication> clientAuthenticationOption() {
      return ConfigOptions.of(
          CLIENT_AUTH, this::clientAuthentication, ClientAuthentication::fromConfigName);
    }

    private ConfigOption<Secret> clientSecretOption() {
      return ConfigOptions.of(CLIENT_SECRET, this::clientSecret, Secret::of);
    }

    private ConfigOption<URI> issuerUrlOption() {
      return ConfigOptions.of(ISSUER_URL, this::issuerUrl, URI::create);
    }

    private ConfigOption<URI> tokenEndpointOption() {
      return ConfigOptions.of(TOKEN_ENDPOINT, this::tokenEndpoint, URI::create);
    }

    private ConfigOption<List<String>> scopesOption() {
      return ConfigOptions.of(SCOPE, this::scopes, ConfigUtils::scopesAsList);
    }

    private ConfigOption<Map<String, String>> extraRequestParametersOption() {
      return ConfigOptions.ofPrefix(EXTRA_PARAMS_PREFIX, this::extraRequestParameters);
    }
  }
}

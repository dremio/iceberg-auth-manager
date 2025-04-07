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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_ID;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.CLIENT_SECRET;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.EXTRA_PARAMS_PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.SCOPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.TOKEN_ENDPOINT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.flow.FlowUtils;
import com.dremio.iceberg.authmgr.oauth2.flow.ServiceAccount;
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
public interface ImpersonationConfig extends ServiceAccount {

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
   * An alternate client ID to use for impersonations only. If not provided, the global client ID
   * will be used. If provided, and if the client is confidential, then its secret must be provided
   * with {@link #getClientSecret()} – the global client secret will NOT be used.
   *
   * @see OAuth2Properties.Impersonation#CLIENT_ID
   */
  @Override
  Optional<String> getClientId();

  /**
   * An alternate client secret supplier to use for impersonations only. If the alternate client
   * obtained from {@link #getClientId()} is confidential, this attribute must be set.
   */
  @Override
  Optional<Secret> getClientSecret();

  /**
   * The root URL of an alternate OpenID Connect identity issuer provider, which will be used for
   * discovering supported endpoints and their locations, but only for impersonation.
   *
   * <p>If neither this property nor {@link #getTokenEndpoint()} are defined, the global token
   * endpoint will be used for impersonation. This means that the same authorization server will be
   * used for both the initial token request and the impersonation token exchange.
   *
   * <p>Endpoint discovery is performed using the OpenID Connect Discovery metadata published by the
   * issuer. See <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect
   * Discovery 1.0</a> for more information.
   *
   * @see OAuth2Properties.Impersonation#ISSUER_URL
   */
  Optional<URI> getIssuerUrl();

  /**
   * An alternate OAuth2 token endpoint, for impersonation only.
   *
   * <p>If neither this property nor {@link #getIssuerUrl()} are defined, the global token endpoint
   * will be used for impersonation. This means that the same authorization server will be used for
   * both the initial token request and the impersonation token exchange.
   *
   * @see OAuth2Properties.Impersonation#TOKEN_ENDPOINT
   */
  Optional<URI> getTokenEndpoint();

  /**
   * Custom OAuth2 scopes for impersonation only. Optional.
   *
   * <p>If not present, the global scopes will be used for impersonation.
   *
   * @see OAuth2Properties.Impersonation#SCOPE
   */
  Optional<List<String>> getScopes();

  /**
   * Additional parameters to be included in the request. This is useful for custom parameters that
   * are not covered by the standard OAuth2.0 specification.
   *
   * <p>If not present, the global extra request parameters, if any, will be used for impersonation.
   */
  Optional<Map<String, String>> getExtraRequestParameters();

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getClientId().isPresent()) {
      validator.check(
          !getClientId().get().isEmpty(), CLIENT_ID, "Impersonation client ID must not be empty");
    }
    if (getIssuerUrl().isPresent()) {
      validator.checkEndpoint(
          getIssuerUrl().get(), true, ISSUER_URL, "Impersonation issuer URL %s");
    }
    if (getTokenEndpoint().isPresent()) {
      validator.checkEndpoint(
          getTokenEndpoint().get(), true, TOKEN_ENDPOINT, "Impersonation token endpoint %s");
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link ImpersonationConfig} and returns the result. */
  default ImpersonationConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    Builder builder = builder();
    builder.enabledOption().merge(properties, isEnabled());
    builder.clientIdOption().merge(properties, getClientId());
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
    Builder scopes(List<String> scopes);

    @CanIgnoreReturnValue
    Builder extraRequestParameters(Map<String, String> extraRequestParameters);

    ImpersonationConfig build();

    private ConfigOption<Boolean> enabledOption() {
      return ConfigOptions.of(ENABLED, this::enabled, Boolean::parseBoolean);
    }

    private ConfigOption<String> clientIdOption() {
      return ConfigOptions.of(CLIENT_ID, this::clientId);
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
      return ConfigOptions.of(SCOPE, this::scopes, FlowUtils::scopesAsList);
    }

    private ConfigOption<Map<String, String>> extraRequestParametersOption() {
      return ConfigOptions.ofPrefix(EXTRA_PARAMS_PREFIX, this::extraRequestParameters);
    }
  }
}

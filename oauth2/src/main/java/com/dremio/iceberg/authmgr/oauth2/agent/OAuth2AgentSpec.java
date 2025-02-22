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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.DIALECT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.GRANT_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Impersonation.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.USERNAME;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode;
import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.config.ImpersonationConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.RuntimeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface OAuth2AgentSpec {

  /**
   * The basic configuration, including token endpoint, grant type, client id and client secret.
   * Required.
   */
  BasicConfig getBasicConfig();

  /** The resource owner configuration. Required for the {@link GrantType#PASSWORD} grant type. */
  @Value.Default
  default ResourceOwnerConfig getResourceOwnerConfig() {
    return ResourceOwnerConfig.DEFAULT;
  }

  /**
   * The authorization code configuration. Required for the {@link GrantType#AUTHORIZATION_CODE}
   * grant type.
   */
  @Value.Default
  default AuthorizationCodeConfig getAuthorizationCodeConfig() {
    return AuthorizationCodeConfig.DEFAULT;
  }

  /** The device code configuration. Required for the {@link GrantType#DEVICE_CODE} grant type. */
  @Value.Default
  default DeviceCodeConfig getDeviceCodeConfig() {
    return DeviceCodeConfig.DEFAULT;
  }

  /** The token refresh configuration. Optional. */
  @Value.Default
  default TokenRefreshConfig getTokenRefreshConfig() {
    return TokenRefreshConfig.DEFAULT;
  }

  /** The token exchange configuration. Optional. */
  @Value.Default
  default TokenExchangeConfig getTokenExchangeConfig() {
    return TokenExchangeConfig.DEFAULT;
  }

  /** The impersonation configuration. Optional. */
  @Value.Default
  default ImpersonationConfig getImpersonationConfig() {
    return ImpersonationConfig.DEFAULT;
  }

  /** The runtime configuration. Optional. */
  @Value.Default
  @Value.Auxiliary
  default RuntimeConfig getRuntimeConfig() {
    return RuntimeConfig.DEFAULT;
  }

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    // We only need to validate constraints that span multiple configuration options here;
    // individual configuration options are validated in their respective classes.
    if (getBasicConfig().getGrantType() == GrantType.PASSWORD) {
      validator.check(
          getResourceOwnerConfig().getUsername().isPresent()
              && !getResourceOwnerConfig().getUsername().get().isEmpty(),
          USERNAME,
          "username must be set if grant type is '%s'",
          GrantType.PASSWORD.getCommonName());
      validator.check(
          getResourceOwnerConfig().getPassword().isPresent(),
          PASSWORD,
          "password must be set if grant type is '%s'",
          GrantType.PASSWORD.getCommonName());
    }
    if (getBasicConfig().getGrantType() == GrantType.AUTHORIZATION_CODE) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getAuthorizationCodeConfig().getAuthorizationEndpoint().isPresent(),
          List.of(ISSUER_URL, AuthorizationCode.ENDPOINT),
          "either issuer URL or authorization endpoint must be set if grant type is '%s'",
          GrantType.AUTHORIZATION_CODE.getCommonName());
    }
    if (getBasicConfig().getGrantType() == GrantType.DEVICE_CODE) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getDeviceCodeConfig().getDeviceAuthorizationEndpoint().isPresent(),
          List.of(ISSUER_URL, DeviceCode.ENDPOINT),
          "either issuer URL or device authorization endpoint must be set if grant type is '%s'",
          GrantType.DEVICE_CODE.getCommonName());
    }
    if (getBasicConfig().getGrantType() == GrantType.TOKEN_EXCHANGE) {
      validator.check(
          !getImpersonationConfig().isEnabled(),
          List.of(ENABLED, GRANT_TYPE),
          "impersonation cannot be enabled if grant type is '%s'",
          GrantType.TOKEN_EXCHANGE.getCommonName());
    }
    if (getBasicConfig().getDialect() == Dialect.ICEBERG_REST) {
      validator.check(
          !getImpersonationConfig().isEnabled(),
          List.of(ENABLED, DIALECT),
          "Iceberg OAuth2 dialect does not support impersonation");
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link OAuth2AgentSpec} and returns the result. */
  default OAuth2AgentSpec merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    return builder()
        .basicConfig(getBasicConfig().merge(properties))
        .resourceOwnerConfig(getResourceOwnerConfig().merge(properties))
        .authorizationCodeConfig(getAuthorizationCodeConfig().merge(properties))
        .deviceCodeConfig(getDeviceCodeConfig().merge(properties))
        .tokenRefreshConfig(getTokenRefreshConfig().merge(properties))
        .tokenExchangeConfig(getTokenExchangeConfig().merge(properties))
        .impersonationConfig(getImpersonationConfig().merge(properties))
        .runtimeConfig(getRuntimeConfig().merge(properties))
        .build();
  }

  static Builder builder() {
    return ImmutableOAuth2AgentSpec.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(OAuth2AgentSpec spec);

    /**
     * Configures this {@link OAuth2AgentSpec.Builder} with the given properties.
     *
     * @throws NullPointerException if {@code properties} is {@code null}, or a required
     *     configuration option is missing
     * @throws IllegalArgumentException if the configuration is otherwise invalid
     * @see OAuth2Properties
     */
    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      return basicConfig(BasicConfig.builder().from(properties).build())
          .resourceOwnerConfig(ResourceOwnerConfig.builder().from(properties).build())
          .authorizationCodeConfig(AuthorizationCodeConfig.builder().from(properties).build())
          .deviceCodeConfig(DeviceCodeConfig.builder().from(properties).build())
          .tokenRefreshConfig(TokenRefreshConfig.builder().from(properties).build())
          .tokenExchangeConfig(TokenExchangeConfig.builder().from(properties).build())
          .impersonationConfig(ImpersonationConfig.builder().from(properties).build())
          .runtimeConfig(RuntimeConfig.builder().from(properties).build());
    }

    @CanIgnoreReturnValue
    Builder basicConfig(BasicConfig basicConfig);

    @CanIgnoreReturnValue
    Builder resourceOwnerConfig(ResourceOwnerConfig resourceOwnerConfig);

    @CanIgnoreReturnValue
    Builder authorizationCodeConfig(AuthorizationCodeConfig authorizationCodeConfig);

    @CanIgnoreReturnValue
    Builder deviceCodeConfig(DeviceCodeConfig deviceCodeConfig);

    @CanIgnoreReturnValue
    Builder tokenRefreshConfig(TokenRefreshConfig tokenRefreshConfig);

    @CanIgnoreReturnValue
    Builder tokenExchangeConfig(TokenExchangeConfig tokenExchangeConfig);

    @CanIgnoreReturnValue
    Builder impersonationConfig(ImpersonationConfig tokenExchangeConfig);

    @CanIgnoreReturnValue
    Builder runtimeConfig(RuntimeConfig runtimeConfig);

    OAuth2AgentSpec build();
  }
}

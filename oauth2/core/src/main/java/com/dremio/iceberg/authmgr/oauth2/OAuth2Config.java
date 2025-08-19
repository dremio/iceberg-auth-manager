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
package com.dremio.iceberg.authmgr.oauth2;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.CLIENT_AUTH;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic.ISSUER_URL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion.ALGORITHM;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ClientAssertion.PRIVATE_KEY;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.ResourceOwner.USERNAME;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.AuthorizationCode;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode;
import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface OAuth2Config {

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

  /**
   * The client JWT assertion configuration. Required when the client authentication method is
   * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT} or {@link
   * ClientAuthenticationMethod#CLIENT_SECRET_JWT}.
   */
  @Value.Default
  default ClientAssertionConfig getClientAssertionConfig() {
    return ClientAssertionConfig.DEFAULT;
  }

  /**
   * The system-wide configuration. Optional.
   *
   * @implNote This property is marked as {@link Value.Auxiliary} in order to not affect equals and
   *     hashCode computations for {@link OAuth2Config} instances. IOW, two {@link OAuth2Config}
   *     instances that differ only in their system config should be considered equal. This is
   *     important as instances of this class may be used as keys in maps.
   */
  @Value.Default
  @Value.Auxiliary
  default SystemConfig getSystemConfig() {
    return SystemConfig.DEFAULT;
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
          GrantType.PASSWORD.getValue());
      validator.check(
          getResourceOwnerConfig().getPassword().isPresent(),
          PASSWORD,
          "password must be set if grant type is '%s'",
          GrantType.PASSWORD.getValue());
    }
    if (getBasicConfig().getGrantType() == GrantType.AUTHORIZATION_CODE) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getAuthorizationCodeConfig().getAuthorizationEndpoint().isPresent(),
          List.of(ISSUER_URL, AuthorizationCode.ENDPOINT),
          "either issuer URL or authorization endpoint must be set if grant type is '%s'",
          GrantType.AUTHORIZATION_CODE.getValue());
    }
    if (getBasicConfig().getGrantType() == GrantType.DEVICE_CODE) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getDeviceCodeConfig().getDeviceAuthorizationEndpoint().isPresent(),
          List.of(ISSUER_URL, DeviceCode.ENDPOINT),
          "either issuer URL or device authorization endpoint must be set if grant type is '%s'",
          GrantType.DEVICE_CODE.getValue());
    }
    ClientAuthenticationMethod method = getBasicConfig().getClientAuthenticationMethod();
    if (ConfigUtils.requiresJwsAlgorithm(method)) {
      if (method.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
        if (getClientAssertionConfig().getAlgorithm().isPresent()) {
          validator.check(
              JWSAlgorithm.Family.HMAC_SHA.contains(
                  getClientAssertionConfig().getAlgorithm().get()),
              List.of(CLIENT_AUTH, ALGORITHM),
              "client authentication method '%s' is not compatible with JWS algorithm '%s'",
              method.getValue(),
              getClientAssertionConfig().getAlgorithm().get());
        }
        validator.check(
            getClientAssertionConfig().getPrivateKey().isEmpty(),
            List.of(CLIENT_AUTH, PRIVATE_KEY),
            "client authentication method '%s' must not have a private key configured",
            method.getValue());
      }
      if (method.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
        if (getClientAssertionConfig().getAlgorithm().isPresent()) {
          validator.check(
              JWSAlgorithm.Family.SIGNATURE.contains(
                  getClientAssertionConfig().getAlgorithm().get()),
              List.of(CLIENT_AUTH, ALGORITHM),
              "client authentication method '%s' is not compatible with JWS algorithm '%s'",
              method.getValue(),
              getClientAssertionConfig().getAlgorithm().get());
        }
        validator.check(
            getClientAssertionConfig().getPrivateKey().isPresent(),
            List.of(CLIENT_AUTH, PRIVATE_KEY),
            "client authentication method '%s' requires a private key",
            method.getValue());
      }
    }
    validator.validate();
  }

  /** Merges the given properties into this {@link OAuth2Config} and returns the result. */
  default OAuth2Config merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    return builder()
        .basicConfig(getBasicConfig().merge(properties))
        .resourceOwnerConfig(getResourceOwnerConfig().merge(properties))
        .authorizationCodeConfig(getAuthorizationCodeConfig().merge(properties))
        .deviceCodeConfig(getDeviceCodeConfig().merge(properties))
        .tokenRefreshConfig(getTokenRefreshConfig().merge(properties))
        .tokenExchangeConfig(getTokenExchangeConfig().merge(properties))
        .clientAssertionConfig(getClientAssertionConfig().merge(properties))
        .systemConfig(getSystemConfig().merge(properties))
        .build();
  }

  static Builder builder() {
    return ImmutableOAuth2Config.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(OAuth2Config spec);

    /**
     * Configures this {@link OAuth2Config.Builder} with the given properties.
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
          .clientAssertionConfig(ClientAssertionConfig.builder().from(properties).build())
          .systemConfig(SystemConfig.builder().from(properties).build());
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
    Builder clientAssertionConfig(ClientAssertionConfig clientAssertionConfig);

    @CanIgnoreReturnValue
    Builder systemConfig(SystemConfig systemConfig);

    OAuth2Config build();
  }
}

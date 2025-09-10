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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static com.dremio.iceberg.authmgr.oauth2.config.BasicConfig.CLIENT_AUTH;
import static com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig.ALGORITHM;
import static com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig.PRIVATE_KEY;
import static com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig.PASSWORD;
import static com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig.USERNAME;

import com.dremio.iceberg.authmgr.oauth2.config.AuthorizationCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils;
import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.HttpConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.WithName;
import io.smallrye.config.WithParentName;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.eclipse.microprofile.config.spi.ConfigSource;

@ConfigMapping(prefix = PREFIX)
public interface OAuth2Config {

  String PREFIX = "rest.auth.oauth2";

  @WithParentName
  BasicConfig getBasicConfig();

  @WithName(TokenRefreshConfig.GROUP_NAME)
  TokenRefreshConfig getTokenRefreshConfig();

  @WithName(ResourceOwnerConfig.GROUP_NAME)
  ResourceOwnerConfig getResourceOwnerConfig();

  @WithName(AuthorizationCodeConfig.GROUP_NAME)
  AuthorizationCodeConfig getAuthorizationCodeConfig();

  @WithName(DeviceCodeConfig.GROUP_NAME)
  DeviceCodeConfig getDeviceCodeConfig();

  @WithName(TokenExchangeConfig.GROUP_NAME)
  TokenExchangeConfig getTokenExchangeConfig();

  @WithName(ClientAssertionConfig.GROUP_NAME)
  ClientAssertionConfig getClientAssertionConfig();

  @WithName(SystemConfig.GROUP_NAME)
  SystemConfig getSystemConfig();

  @WithName(HttpConfig.GROUP_NAME)
  HttpConfig getHttpConfig();

  /**
   * Creates an {@link OAuth2Config} from the environment and the given catalog session properties
   * map.
   *
   * <p>The resulting configuration is loaded in the following order:
   *
   * <ol>
   *   <li>System properties (ordinal 400)
   *   <li>Environment properties (ordinal 300)
   *   <li>Catalog session properties passed to this method (ordinal 200)
   *   <li>Microprofile config files (ordinal 100)
   * </ol>
   *
   * Support for custom configuration files can be achieved with the {@code
   * smallrye.config.locations} configuration property. See <a
   * href="https://smallrye.io/smallrye-config/Main/config-sources/locations/">SmallRye Config
   * Locations</a> for more details.
   *
   * @param properties The catalog session properties to create the config from.
   */
  static OAuth2Config from(Map<String, String> properties) {
    MapBackedConfigSource source =
        new MapBackedConfigSource("catalog session properties", properties, 200) {};
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .addDefaultSources()
            .withSources(source)
            .withMapping(OAuth2Config.class)
            .build();
    OAuth2Config config = smallRyeConfig.getConfigMapping(OAuth2Config.class);
    config.validate();
    return config;
  }

  /**
   * Merges the given properties into this {@link OAuth2Config} and returns the result.
   *
   * <p>This method is used to merge the properties from the parent (catalog) session with the
   * properties from the table or context properties.
   *
   * <p>The properties are loaded in the following order:
   *
   * <ol>
   *   <li>Child session properties (ordinal 2000)
   *   <li>Parent session properties (ordinal 1000)
   * </ol>
   *
   * This method does not load any other properties from the system, environment, or config files,
   * as the parent session properties already contain properties sourced from those sources.
   */
  default OAuth2Config merge(Map<String, String> childProperties) {
    Objects.requireNonNull(childProperties, "childProperties must not be null");
    ConfigSource childSource =
        new MapBackedConfigSource("child session properties", childProperties, 2000) {};
    ConfigSource parentSource =
        new MapBackedConfigSource("parent session properties", asMap(), 1000) {};
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withSources(childSource, parentSource)
            .withMapping(OAuth2Config.class)
            .build();
    OAuth2Config config = smallRyeConfig.getConfigMapping(OAuth2Config.class);
    config.validate();
    return config;
  }

  default void validate() {
    // Validate individual configuration classes
    getBasicConfig().validate();
    getAuthorizationCodeConfig().validate();
    getDeviceCodeConfig().validate();
    getTokenRefreshConfig().validate();
    getTokenExchangeConfig().validate();
    getClientAssertionConfig().validate();
    getSystemConfig().validate();
    getHttpConfig().validate();
    // Validate constraints that span multiple configuration classes
    ConfigValidator validator = new ConfigValidator();
    GrantType grantType = getBasicConfig().getGrantType();
    if (grantType.equals(GrantType.PASSWORD)) {
      validator.check(
          getResourceOwnerConfig().getUsername().isPresent()
              && !getResourceOwnerConfig().getUsername().get().isEmpty(),
          ResourceOwnerConfig.PREFIX + '.' + USERNAME,
          "username must be set if grant type is '%s'",
          GrantType.PASSWORD.getValue());
      validator.check(
          getResourceOwnerConfig().getPassword().isPresent(),
          ResourceOwnerConfig.PREFIX + '.' + PASSWORD,
          "password must be set if grant type is '%s'",
          GrantType.PASSWORD.getValue());
    }
    if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getAuthorizationCodeConfig().getAuthorizationEndpoint().isPresent(),
          List.of(
              PREFIX + '.' + BasicConfig.ISSUER_URL,
              AuthorizationCodeConfig.PREFIX + '.' + AuthorizationCodeConfig.ENDPOINT),
          "either issuer URL or authorization endpoint must be set if grant type is '%s'",
          GrantType.AUTHORIZATION_CODE.getValue());
    }
    if (grantType.equals(GrantType.DEVICE_CODE)) {
      validator.check(
          getBasicConfig().getIssuerUrl().isPresent()
              || getDeviceCodeConfig().getDeviceAuthorizationEndpoint().isPresent(),
          List.of(
              PREFIX + '.' + BasicConfig.ISSUER_URL,
              DeviceCodeConfig.PREFIX + '.' + DeviceCodeConfig.ENDPOINT),
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
              List.of(PREFIX + '.' + CLIENT_AUTH, ClientAssertionConfig.PREFIX + '.' + ALGORITHM),
              "client authentication method '%s' is not compatible with JWS algorithm '%s'",
              method.getValue(),
              getClientAssertionConfig().getAlgorithm().get());
        }
        validator.check(
            getClientAssertionConfig().getPrivateKey().isEmpty(),
            List.of(PREFIX + '.' + CLIENT_AUTH, ClientAssertionConfig.PREFIX + '.' + PRIVATE_KEY),
            "client authentication method '%s' must not have a private key configured",
            method.getValue());
      }
      if (method.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
        if (getClientAssertionConfig().getAlgorithm().isPresent()) {
          validator.check(
              JWSAlgorithm.Family.SIGNATURE.contains(
                  getClientAssertionConfig().getAlgorithm().get()),
              List.of(PREFIX + '.' + CLIENT_AUTH, ClientAssertionConfig.PREFIX + '.' + ALGORITHM),
              "client authentication method '%s' is not compatible with JWS algorithm '%s'",
              method.getValue(),
              getClientAssertionConfig().getAlgorithm().get());
        }
        validator.check(
            getClientAssertionConfig().getPrivateKey().isPresent(),
            List.of(PREFIX + '.' + CLIENT_AUTH, ClientAssertionConfig.PREFIX + '.' + PRIVATE_KEY),
            "client authentication method '%s' requires a private key",
            method.getValue());
      }
    }
    validator.validate();
  }

  /** Returns all properties in this config as a flattened map. */
  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    properties.putAll(getBasicConfig().asMap());
    properties.putAll(getResourceOwnerConfig().asMap());
    properties.putAll(getAuthorizationCodeConfig().asMap());
    properties.putAll(getDeviceCodeConfig().asMap());
    properties.putAll(getTokenRefreshConfig().asMap());
    properties.putAll(getTokenExchangeConfig().asMap());
    properties.putAll(getClientAssertionConfig().asMap());
    properties.putAll(getSystemConfig().asMap());
    properties.putAll(getHttpConfig().asMap());
    return Map.copyOf(properties);
  }
}

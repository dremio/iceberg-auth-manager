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
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for the <a href="https://datatracker.ietf.org/doc/html/rfc8628">Device
 * Authorization Grant</a> flow.
 *
 * <p>This flow is used to obtain an access token for devices that do not have a browser or limited
 * input capabilities. The user is prompted to visit a URL on another device and enter a code to
 * authorize the device.
 */
public interface DeviceCodeConfig {

  String GROUP_NAME = "device-code";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ENDPOINT = "endpoint";
  String POLL_INTERVAL = "poll-interval";

  String DEFAULT_POLL_INTERVAL = "PT5S";

  /**
   * URL of the OAuth2 device authorization endpoint. For Keycloak, this is typically {@code
   * http://<keycloak-server>/realms/<realm-name>/protocol/openid-connect/auth/device}.
   *
   * <p>If using the "Device Code" grant type, either this property or {@link
   * BasicConfig#ISSUER_URL} must be set.
   */
  @WithName(ENDPOINT)
  Optional<URI> getDeviceAuthorizationEndpoint();

  /**
   * Defines how often the agent should poll the OAuth2 server for the device code flow to complete.
   * This is only used if the grant type to use is {@link GrantType#DEVICE_CODE}. Optional, defaults
   * to {@value #DEFAULT_POLL_INTERVAL}.
   */
  @WithName(POLL_INTERVAL)
  @WithDefault(DEFAULT_POLL_INTERVAL)
  Duration getPollInterval();

  /**
   * The minimum poll interval for the device code flow. The device code flow requires a minimum
   * poll interval of 5 seconds.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("min-poll-interval")
  @WithDefault(DEFAULT_POLL_INTERVAL) // mandated by the specs
  Duration getMinPollInterval();

  /**
   * Whether to ignore the server-specified poll interval and always use the configured poll
   * interval.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("ignore-server-poll-interval")
  @WithDefault("false")
  boolean ignoreServerPollInterval();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getDeviceAuthorizationEndpoint().isPresent()) {
      validator.checkEndpoint(
          getDeviceAuthorizationEndpoint().get(),
          PREFIX + '.' + ENDPOINT,
          "device code flow: device authorization endpoint");
    }
    validator.check(
        getPollInterval().compareTo(getMinPollInterval()) >= 0,
        PREFIX + '.' + POLL_INTERVAL,
        "device code flow: poll interval must be greater than or equal to %s",
        getMinPollInterval());
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    getDeviceAuthorizationEndpoint()
        .ifPresent(u -> properties.put(PREFIX + '.' + ENDPOINT, u.toString()));
    properties.put(PREFIX + '.' + POLL_INTERVAL, getPollInterval().toString());
    properties.put(PREFIX + '.' + "min-poll-interval", getMinPollInterval().toString());
    properties.put(
        PREFIX + '.' + "ignore-server-poll-interval", String.valueOf(ignoreServerPollInterval()));
    return Map.copyOf(properties);
  }
}

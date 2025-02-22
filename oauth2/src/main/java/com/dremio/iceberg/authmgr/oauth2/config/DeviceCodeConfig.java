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
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.ENDPOINT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.POLL_INTERVAL;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.DeviceCode.TIMEOUT;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface DeviceCodeConfig {

  DeviceCodeConfig DEFAULT = builder().build();

  /**
   * The OAuth2 device authorization endpoint. Either this or {@link BasicConfig#getIssuerUrl()}
   * must be set, if the grant type is {@link GrantType#DEVICE_CODE}. This is the endpoint where the
   * device authorization request will be sent to.
   *
   * @see OAuth2Properties.DeviceCode#ENDPOINT
   */
  Optional<URI> getDeviceAuthorizationEndpoint();

  /**
   * How long to wait for the device code flow to complete. Defaults to {@link
   * OAuth2Properties.DeviceCode#DEFAULT_TIMEOUT}. Only relevant when using the {@link
   * GrantType#DEVICE_CODE} grant type.
   *
   * @see OAuth2Properties.DeviceCode#TIMEOUT
   */
  @Value.Default
  default Duration getTimeout() {
    return ConfigConstants.DEVICE_CODE_DEFAULT_TIMEOUT;
  }

  /**
   * How often to poll the token endpoint. Defaults to {@link
   * OAuth2Properties.DeviceCode#DEFAULT_POLL_INTERVAL}. Only relevant when using the {@link
   * GrantType#DEVICE_CODE} grant type.
   *
   * @see OAuth2Properties.DeviceCode#POLL_INTERVAL
   */
  @Value.Default
  default Duration getPollInterval() {
    return ConfigConstants.DEVICE_CODE_DEFAULT_POLL_INTERVAL;
  }

  /**
   * The minimum timeout for the device code flow.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinTimeout() {
    return ConfigConstants.DEVICE_CODE_MIN_TIMEOUT;
  }

  /**
   * The minimum poll interval for the device code flow. The device code flow requires a minimum
   * poll interval of 5 seconds.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinPollInterval() {
    return ConfigConstants.DEVICE_CODE_MIN_POLL_INTERVAL;
  }

  /**
   * Whether to ignore the server-specified poll interval and always use the configured poll
   * interval.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default boolean ignoreServerPollInterval() {
    return false;
  }

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    if (getDeviceAuthorizationEndpoint().isPresent()) {
      validator.checkEndpoint(
          getDeviceAuthorizationEndpoint().get(),
          true,
          ENDPOINT,
          "device code flow: device authorization endpoint %s");
    }
    validator.check(
        getPollInterval().compareTo(getMinPollInterval()) >= 0,
        POLL_INTERVAL,
        "device code flow: poll interval must be greater than or equal to %s",
        getMinPollInterval());
    validator.check(
        getTimeout().compareTo(getMinTimeout()) >= 0,
        TIMEOUT,
        "device code flow: timeout must be greater than or equal to %s",
        getMinTimeout());
    validator.validate();
  }

  /** Merges the given properties into this {@link DeviceCodeConfig} and returns the result. */
  default DeviceCodeConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    DeviceCodeConfig.Builder builder = builder();
    builder.deviceAuthorizationEndpointOption().merge(properties, getDeviceAuthorizationEndpoint());
    builder.timeoutOption().merge(properties, getTimeout());
    builder.pollIntervalOption().merge(properties, getPollInterval());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableDeviceCodeConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(DeviceCodeConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      deviceAuthorizationEndpointOption().apply(properties);
      timeoutOption().apply(properties);
      pollIntervalOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder deviceAuthorizationEndpoint(URI deviceAuthorizationEndpoint);

    @CanIgnoreReturnValue
    Builder timeout(Duration timeout);

    @CanIgnoreReturnValue
    Builder pollInterval(Duration pollInterval);

    @CanIgnoreReturnValue
    Builder minTimeout(Duration minTimeout);

    @CanIgnoreReturnValue
    Builder minPollInterval(Duration minPollInterval);

    @CanIgnoreReturnValue
    Builder ignoreServerPollInterval(boolean ignoreServerPollInterval);

    DeviceCodeConfig build();

    private ConfigOption<URI> deviceAuthorizationEndpointOption() {
      return ConfigOptions.of(ENDPOINT, this::deviceAuthorizationEndpoint, URI::create);
    }

    private ConfigOption<Duration> timeoutOption() {
      return ConfigOptions.of(TIMEOUT, this::timeout, Duration::parse);
    }

    private ConfigOption<Duration> pollIntervalOption() {
      return ConfigOptions.of(POLL_INTERVAL, this::pollInterval, Duration::parse);
    }
  }
}

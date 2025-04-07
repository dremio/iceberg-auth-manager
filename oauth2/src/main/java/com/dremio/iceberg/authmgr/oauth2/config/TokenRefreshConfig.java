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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.ACCESS_TOKEN_LIFESPAN;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.ENABLED;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.IDLE_TIMEOUT;
import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenRefresh.SAFETY_WINDOW;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface TokenRefreshConfig {

  TokenRefreshConfig DEFAULT = builder().build();

  /**
   * Whether token refresh is enabled. If enabled, the agent will automatically refresh the access
   * token when it expires. If disabled, the agent will only fetch the initial access token, but
   * won't refresh it. Optional, defaults to {@code true}.
   *
   * @see OAuth2Properties.TokenRefresh#ENABLED
   */
  @Value.Default
  default boolean isEnabled() {
    return true;
  }

  /**
   * The default access token lifespan; if the OAuth2 server returns an access token without
   * specifying its expiration time, this value will be used. Note that when this happens, a warning
   * will be logged. Optional, defaults to {@link
   * OAuth2Properties.TokenRefresh#DEFAULT_ACCESS_TOKEN_LIFESPAN}.
   *
   * @see OAuth2Properties.TokenRefresh#ACCESS_TOKEN_LIFESPAN
   */
  @Value.Default
  default Duration getAccessTokenLifespan() {
    return ConfigConstants.TOKEN_REFRESH_DEFAULT_ACCESS_TOKEN_LIFESPAN;
  }

  /**
   * The refresh safety window. A new token will be fetched when the current token's remaining
   * lifespan is less than this value. Optional, defaults to {@link
   * OAuth2Properties.TokenRefresh#DEFAULT_SAFETY_WINDOW}.
   *
   * @see OAuth2Properties.TokenRefresh#SAFETY_WINDOW
   */
  @Value.Default
  default Duration getSafetyWindow() {
    return ConfigConstants.TOKEN_REFRESH_DEFAULT_SAFETY_WINDOW;
  }

  /**
   * For how long the OAuth2 client should keep the tokens fresh, if the agent is not being actively
   * used. Defaults to {@link OAuth2Properties.TokenRefresh#DEFAULT_IDLE_TIMEOUT}.
   *
   * @see OAuth2Properties.TokenRefresh#IDLE_TIMEOUT
   */
  @Value.Default
  default Duration getIdleTimeout() {
    return ConfigConstants.TOKEN_REFRESH_DEFAULT_IDLE_TIMEOUT;
  }

  /**
   * The minimum access token lifespan. Optional, defaults to {@code 30 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinAccessTokenLifespan() {
    return ConfigConstants.TOKEN_REFRESH_MIN_ACCESS_TOKEN_LIFESPAN;
  }

  /**
   * The minimum refresh safety window. Optional, defaults to {@code 5 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinRefreshDelay() {
    return ConfigConstants.TOKEN_REFRESH_MIN_REFRESH_DELAY;
  }

  /**
   * The minimum token refresh idle timeout. Optional, defaults to {@code 30 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  default Duration getMinIdleTimeout() {
    return ConfigConstants.TOKEN_REFRESH_MIN_IDLE_TIMEOUT;
  }

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    validator.check(
        getAccessTokenLifespan().compareTo(getMinAccessTokenLifespan()) >= 0,
        ACCESS_TOKEN_LIFESPAN,
        "access token lifespan must be greater than or equal to %s",
        getMinAccessTokenLifespan());
    validator.check(
        getSafetyWindow().compareTo(getMinRefreshDelay()) >= 0,
        SAFETY_WINDOW,
        "refresh safety window must be greater than or equal to %s",
        getMinRefreshDelay());
    validator.check(
        getSafetyWindow().compareTo(getAccessTokenLifespan()) < 0,
        List.of(SAFETY_WINDOW, ACCESS_TOKEN_LIFESPAN),
        "refresh safety window must be less than the access token lifespan");
    validator.check(
        getIdleTimeout().compareTo(getMinIdleTimeout()) >= 0,
        IDLE_TIMEOUT,
        "token refresh idle timeout must be greater than or equal to %s",
        getMinIdleTimeout());
    validator.validate();
  }

  /** Merges the given properties into this {@link TokenRefreshConfig} and returns the result. */
  default TokenRefreshConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    TokenRefreshConfig.Builder builder = builder();
    builder.enabledOption().merge(properties, isEnabled());
    builder.accessTokenLifespanOption().merge(properties, getAccessTokenLifespan());
    builder.safetyWindowOption().merge(properties, getSafetyWindow());
    builder.idleTimeoutOption().merge(properties, getIdleTimeout());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableTokenRefreshConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(TokenRefreshConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      enabledOption().apply(properties);
      accessTokenLifespanOption().apply(properties);
      safetyWindowOption().apply(properties);
      idleTimeoutOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder enabled(boolean enabled);

    @CanIgnoreReturnValue
    Builder accessTokenLifespan(Duration accessTokenLifespan);

    @CanIgnoreReturnValue
    Builder safetyWindow(Duration safetyWindow);

    @CanIgnoreReturnValue
    Builder idleTimeout(Duration idleTimeout);

    Builder minAccessTokenLifespan(Duration minAccessTokenLifespan);

    @CanIgnoreReturnValue
    Builder minRefreshDelay(Duration minRefreshDelay);

    @CanIgnoreReturnValue
    Builder minIdleTimeout(Duration minIdleTimeout);

    TokenRefreshConfig build();

    private ConfigOption<Boolean> enabledOption() {
      return ConfigOptions.of(ENABLED, this::enabled, Boolean::parseBoolean);
    }

    private ConfigOption<Duration> accessTokenLifespanOption() {
      return ConfigOptions.of(ACCESS_TOKEN_LIFESPAN, this::accessTokenLifespan, Duration::parse);
    }

    private ConfigOption<Duration> safetyWindowOption() {
      return ConfigOptions.of(SAFETY_WINDOW, this::safetyWindow, Duration::parse);
    }

    private ConfigOption<Duration> idleTimeoutOption() {
      return ConfigOptions.of(IDLE_TIMEOUT, this::idleTimeout, Duration::parse);
    }
  }
}

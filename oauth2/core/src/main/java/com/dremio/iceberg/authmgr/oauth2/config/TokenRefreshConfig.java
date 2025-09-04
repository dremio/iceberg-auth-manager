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
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Configuration properties for the token refresh feature. */
public interface TokenRefreshConfig {

  String GROUP_NAME = "token-refresh";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String ENABLED = "enabled";

  String ACCESS_TOKEN_LIFESPAN = "access-token-lifespan";
  String SAFETY_WINDOW = "safety-window";
  String IDLE_TIMEOUT = "idle-timeout";

  String DEFAULT_ACCESS_TOKEN_LIFESPAN = "PT5M";
  String DEFAULT_SAFETY_WINDOW = "PT10S";
  String DEFAULT_IDLE_TIMEOUT = "PT30S";

  /**
   * Whether to enable token refresh. If enabled, the agent will automatically refresh its access
   * token when it expires. If disabled, the agent will only fetch the initial access token, but
   * won't refresh it. Defaults to {@code true}.
   */
  @WithName(ENABLED)
  @WithDefault("true")
  boolean isEnabled();

  /**
   * Default access token lifespan; if the OAuth2 server returns an access token without specifying
   * its expiration time, this value will be used. Note that when this happens, a warning will be
   * logged.
   *
   * <p>Optional, defaults to {@value #DEFAULT_ACCESS_TOKEN_LIFESPAN}. Must be a valid <a
   * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   */
  @WithName(ACCESS_TOKEN_LIFESPAN)
  @WithDefault(DEFAULT_ACCESS_TOKEN_LIFESPAN)
  Duration getAccessTokenLifespan();

  /**
   * Refresh safety window to use; a new token will be fetched when the current token's remaining
   * lifespan is less than this value. Optional, defaults to {@value #DEFAULT_SAFETY_WINDOW}. Must
   * be a valid <a href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   */
  @WithName(SAFETY_WINDOW)
  @WithDefault(DEFAULT_SAFETY_WINDOW)
  Duration getSafetyWindow();

  /**
   * Defines for how long the OAuth2 manager should keep the tokens fresh, if the agent is not being
   * actively used. Setting this value too high may cause an excessive usage of network I/O and
   * thread resources; conversely, when setting it too low, if the agent is used again, the calling
   * thread may block if the tokens are expired and need to be renewed synchronously. Optional,
   * defaults to {@value #DEFAULT_IDLE_TIMEOUT}. Must be a valid <a
   * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   */
  @WithName(IDLE_TIMEOUT)
  @WithDefault(DEFAULT_IDLE_TIMEOUT)
  Duration getIdleTimeout();

  /**
   * The minimum access token lifespan. Optional, defaults to {@code 30 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("min-access-token-lifespan")
  @WithDefault("PT30S")
  Duration getMinAccessTokenLifespan();

  /**
   * The minimum refresh safety window. Optional, defaults to {@code 5 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("min-refresh-delay")
  @WithDefault("PT5S")
  Duration getMinRefreshDelay();

  /**
   * The minimum token refresh idle timeout. Optional, defaults to {@code 30 seconds}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @WithName("min-idle-timeout")
  @WithDefault("PT30S")
  Duration getMinIdleTimeout();

  default void validate() {
    if (isEnabled()) {
      ConfigValidator validator = new ConfigValidator();
      validator.check(
          getAccessTokenLifespan().compareTo(getMinAccessTokenLifespan()) >= 0,
          PREFIX + '.' + ACCESS_TOKEN_LIFESPAN,
          "access token lifespan must be greater than or equal to %s",
          getMinAccessTokenLifespan());
      validator.check(
          getSafetyWindow().compareTo(getMinRefreshDelay()) >= 0,
          PREFIX + '.' + SAFETY_WINDOW,
          "refresh safety window must be greater than or equal to %s",
          getMinRefreshDelay());
      validator.check(
          getSafetyWindow().compareTo(getAccessTokenLifespan()) < 0,
          List.of(PREFIX + '.' + SAFETY_WINDOW, PREFIX + '.' + ACCESS_TOKEN_LIFESPAN),
          "refresh safety window must be less than the access token lifespan");
      validator.check(
          getIdleTimeout().compareTo(getMinIdleTimeout()) >= 0,
          PREFIX + '.' + IDLE_TIMEOUT,
          "token refresh idle timeout must be greater than or equal to %s",
          getMinIdleTimeout());
      validator.validate();
    }
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    properties.put(PREFIX + '.' + ENABLED, String.valueOf(isEnabled()));
    properties.put(PREFIX + '.' + ACCESS_TOKEN_LIFESPAN, getAccessTokenLifespan().toString());
    properties.put(PREFIX + '.' + SAFETY_WINDOW, getSafetyWindow().toString());
    properties.put(PREFIX + '.' + IDLE_TIMEOUT, getIdleTimeout().toString());
    properties.put(
        PREFIX + '.' + "min-access-token-lifespan", getMinAccessTokenLifespan().toString());
    properties.put(PREFIX + '.' + "min-refresh-delay", getMinRefreshDelay().toString());
    properties.put(PREFIX + '.' + "min-idle-timeout", getMinIdleTimeout().toString());
    return Map.copyOf(properties);
  }
}

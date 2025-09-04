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
import java.util.Map;

/**
 * Configuration properties for the whole system.
 *
 * <p>These properties are used to configure properties such as the session cache timeout.
 */
public interface SystemConfig {

  String GROUP_NAME = "system";
  String PREFIX = OAuth2Config.PREFIX + '.' + GROUP_NAME;

  String AGENT_NAME = "agent-name";
  String SESSION_CACHE_TIMEOUT = "session-cache-timeout";

  String DEFAULT_AGENT_NAME = "iceberg-auth-manager";
  String DEFAULT_SESSION_CACHE_TIMEOUT = "PT1H";

  /**
   * The distinctive name of the OAuth2 agent. Defaults to {@value #DEFAULT_AGENT_NAME}. This name
   * is printed in all log messages and user prompts.
   */
  @WithName(AGENT_NAME)
  @WithDefault(DEFAULT_AGENT_NAME)
  String getAgentName();

  /**
   * The session cache timeout. Cached sessions will become eligible for eviction after this
   * duration of inactivity. Defaults to {@value #DEFAULT_SESSION_CACHE_TIMEOUT}. Must be a valid <a
   * href="https://en.wikipedia.org/wiki/ISO_8601#Durations">ISO-8601 duration</a>.
   *
   * <p>This value is used for housekeeping; it does not mean that cached sessions will stop working
   * after this time, but that the session cache will evict the session after this time of
   * inactivity. If the context is used again, a new session will be created and cached.
   */
  @WithName(SESSION_CACHE_TIMEOUT)
  @WithDefault(DEFAULT_SESSION_CACHE_TIMEOUT)
  Duration getSessionCacheTimeout();

  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    validator.check(
        !getAgentName().isBlank(), PREFIX + '.' + AGENT_NAME, "agent name must not be blank");
    validator.validate();
  }

  default Map<String, String> asMap() {
    Map<String, String> properties = new HashMap<>();
    properties.put(PREFIX + '.' + AGENT_NAME, getAgentName());
    properties.put(PREFIX + '.' + SESSION_CACHE_TIMEOUT, getSessionCacheTimeout().toString());
    return Map.copyOf(properties);
  }
}

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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Runtime.AGENT_NAME;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOption;
import com.dremio.iceberg.authmgr.oauth2.config.option.ConfigOptions;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.PrintStream;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
public interface RuntimeConfig {

  RuntimeConfig DEFAULT = builder().build();

  /**
   * The distinctive name of the OAuth2 agent. Defaults to {@value
   * OAuth2Properties.Runtime#DEFAULT_AGENT_NAME}. This name is printed in all log messages and user
   * prompts.
   *
   * @see OAuth2Properties.Runtime#AGENT_NAME
   */
  @Value.Default
  default String getAgentName() {
    return OAuth2Properties.Runtime.DEFAULT_AGENT_NAME;
  }

  /**
   * The clock to use for time-based operations. Defaults to the system clock.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  @Value.Auxiliary
  default Clock getClock() {
    return Clock.systemUTC();
  }

  /**
   * The {@link PrintStream} to use for console output. Defaults to {@link System#out}.
   *
   * <p>This setting is not exposed as a configuration option and is intended for testing purposes.
   *
   * @hidden
   */
  @Value.Default
  @Value.Auxiliary
  default PrintStream getConsole() {
    return System.out;
  }

  @Value.Check
  default void validate() {
    ConfigValidator validator = new ConfigValidator();
    validator.check(!getAgentName().isBlank(), AGENT_NAME, "agent name must not be blank");
    validator.validate();
  }

  /** Merges the given properties into this {@link RuntimeConfig} and returns the result. */
  default RuntimeConfig merge(Map<String, String> properties) {
    Objects.requireNonNull(properties, "properties must not be null");
    RuntimeConfig.Builder builder = builder();
    builder.agentNameOption().merge(properties, getAgentName());
    builder.clock(getClock());
    builder.console(getConsole());
    return builder.build();
  }

  static Builder builder() {
    return ImmutableRuntimeConfig.builder();
  }

  interface Builder {

    @CanIgnoreReturnValue
    Builder from(RuntimeConfig config);

    @CanIgnoreReturnValue
    default Builder from(Map<String, String> properties) {
      Objects.requireNonNull(properties, "properties must not be null");
      agentNameOption().apply(properties);
      return this;
    }

    @CanIgnoreReturnValue
    Builder agentName(String agentName);

    @CanIgnoreReturnValue
    Builder clock(Clock clock);

    @CanIgnoreReturnValue
    Builder console(PrintStream console);

    RuntimeConfig build();

    private ConfigOption<String> agentNameOption() {
      return ConfigOptions.of(AGENT_NAME, this::agentName);
    }
  }
}

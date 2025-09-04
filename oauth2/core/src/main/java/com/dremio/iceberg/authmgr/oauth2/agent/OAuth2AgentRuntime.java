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
package com.dremio.iceberg.authmgr.oauth2.agent;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.io.PrintStream;
import java.time.Clock;
import java.util.concurrent.ScheduledExecutorService;
import org.immutables.value.Value;

/**
 * A runtime context for the OAuth2 agent.
 *
 * <p>This component groups together agent dependencies that are not part of the agent's
 * configuration, but rather are provided by the environment.
 */
@AuthManagerImmutable
public interface OAuth2AgentRuntime {

  static OAuth2AgentRuntime of(ScheduledExecutorService executor) {
    return ImmutableOAuth2AgentRuntime.builder().executor(executor).build();
  }

  /** The executor to use for asynchronous operations. */
  ScheduledExecutorService getExecutor();

  /** The clock to use for time-based operations. Defaults to the system clock. */
  @Value.Default
  default Clock getClock() {
    return Clock.systemUTC();
  }

  /** The {@link PrintStream} to use for console output. Defaults to {@link System#out}. */
  @Value.Default
  default PrintStream getConsole() {
    return System.out;
  }
}

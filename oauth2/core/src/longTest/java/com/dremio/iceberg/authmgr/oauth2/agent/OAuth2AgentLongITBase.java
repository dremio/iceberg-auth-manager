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

import static java.util.concurrent.CompletableFuture.delayedExecutor;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.LongSupplier;

public abstract class OAuth2AgentLongITBase {

  private final Duration total =
      Duration.parse(System.getProperty("authmgr.it.long.total", "PT30S"));

  private final LongSupplier shortDelay = () -> (long) (Math.random() * 5);
  private final LongSupplier longDelay = () -> 10 + (long) (Math.random() * 20);

  private CompletableFuture<Void> stop;

  protected void run(Builder envBuilder1, Builder envBuilder2)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env1 = envBuilder1.build();
        TestEnvironment env2 = envBuilder2.build();
        OAuth2Agent fast = env1.newAgent();
        OAuth2Agent slow = env2.newAgent()) {
      stop = CompletableFuture.runAsync(() -> {}, delayedExecutor(total.toSeconds(), SECONDS));
      CompletableFuture<Void> future1 = schedule(fast, shortDelay);
      CompletableFuture<Void> future2 = schedule(slow, longDelay);
      stop.get();
      future1.complete(null);
      future2.complete(null);
      assertThat(future1).isNotCompletedExceptionally();
      assertThat(future2).isNotCompletedExceptionally();
    }
  }

  private CompletableFuture<Void> schedule(OAuth2Agent agent, LongSupplier nextDelay) {
    return CompletableFuture.runAsync(() -> authenticate(agent))
        .whenComplete(
            (result, error) -> {
              if (error != null) {
                stop.completeExceptionally(error);
              }
            })
        .thenComposeAsync(
            v -> schedule(agent, nextDelay), delayedExecutor(nextDelay.getAsLong(), SECONDS));
  }

  protected abstract void authenticate(OAuth2Agent agent);
}

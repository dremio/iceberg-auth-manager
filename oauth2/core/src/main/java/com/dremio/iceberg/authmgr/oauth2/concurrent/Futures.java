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
package com.dremio.iceberg.authmgr.oauth2.concurrent;

import jakarta.annotation.Nullable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

/** Utilities for working with futures. */
public final class Futures {

  private Futures() {}

  /**
   * Returns the value of the given stage if it is already completed successfully, or null
   * otherwise. Similar to {@link CompletableFuture#getNow(Object)} but doesn't throw if the stage
   * is completed exceptionally.
   */
  @Nullable
  public static <T> T getNow(@Nullable CompletableFuture<T> future) {
    if (future != null) {
      if (future.isDone() && !future.isCompletedExceptionally() && !future.isCancelled()) {
        return future.join();
      }
    }
    return null;
  }

  /** Cancels the given future if it is not null. */
  public static void cancel(@Nullable Future<?> future) {
    if (future != null) {
      future.cancel(true);
    }
  }
}

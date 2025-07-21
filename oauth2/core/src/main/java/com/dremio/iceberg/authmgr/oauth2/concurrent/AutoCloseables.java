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
import java.util.concurrent.Future;

public final class AutoCloseables {

  public interface UncheckedAutoCloseable extends AutoCloseable {
    @Override
    void close();
  }

  public static final UncheckedAutoCloseable NO_OP = () -> {};

  private AutoCloseables() {}

  /** Returns an {@link UncheckedAutoCloseable} that runs the given runnable when closed. */
  public static UncheckedAutoCloseable runOnClose(@Nullable Runnable runnable) {
    return runnable == null ? NO_OP : runnable::run;
  }

  /** Returns an {@link UncheckedAutoCloseable} that cancels the given future when closed. */
  public static UncheckedAutoCloseable cancelOnClose(@Nullable Future<?> future) {
    return future == null ? NO_OP : runOnClose(() -> Futures.cancel(future));
  }
}

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.dremio.iceberg.authmgr.oauth2.concurrent.AutoCloseables.UncheckedAutoCloseable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class AutoCloseablesTest {

  @Test
  void runOnClose() {
    UncheckedAutoCloseable closeable = AutoCloseables.runOnClose(null);
    assertThatCode(closeable::close).doesNotThrowAnyException();
  }

  @Test
  void runOnCloseWithRunnable() {
    AtomicBoolean executed = new AtomicBoolean(false);
    Runnable runnable = () -> executed.set(true);
    UncheckedAutoCloseable closeable = AutoCloseables.runOnClose(runnable);
    assertThat(executed).isFalse();
    closeable.close();
    assertThat(executed).isTrue();
  }

  @Test
  void runOnCloseWithExceptionInRunnable() {
    Runnable throwingRunnable =
        () -> {
          throw new RuntimeException("Test exception");
        };
    UncheckedAutoCloseable closeable = AutoCloseables.runOnClose(throwingRunnable);
    assertThatCode(closeable::close)
        .isInstanceOf(RuntimeException.class)
        .hasMessage("Test exception");
  }

  @Test
  void cancelOnCloseWithNullFuture() {
    UncheckedAutoCloseable closeable = AutoCloseables.cancelOnClose(null);
    assertThatCode(closeable::close).doesNotThrowAnyException();
  }

  @Test
  void cancelOnCloseWithFuture() {
    CompletableFuture<String> future = new CompletableFuture<>();
    UncheckedAutoCloseable closeable = AutoCloseables.cancelOnClose(future);
    assertThat(future.isCancelled()).isFalse();
    closeable.close();
    assertThat(future.isCancelled()).isTrue();
    assertThat(future.isDone()).isTrue();
    assertThat(future.isCompletedExceptionally()).isTrue();
  }

  @Test
  void cancelOnCloseWithCompletedFuture() {
    CompletableFuture<String> future = CompletableFuture.completedFuture("test");
    UncheckedAutoCloseable closeable = AutoCloseables.cancelOnClose(future);
    assertThatCode(closeable::close).doesNotThrowAnyException();
    assertThat(future.isDone()).isTrue();
    assertThat(future.isCancelled()).isFalse();
    assertThat(future.isCompletedExceptionally()).isFalse();
  }

  @Test
  void cancelOnCloseWithFailedFuture() {
    Future<?> mockFuture = mock(Future.class);
    when(mockFuture.cancel(true)).thenThrow(new RuntimeException("Cancel failed"));
    UncheckedAutoCloseable closeable = AutoCloseables.cancelOnClose(mockFuture);
    assertThatThrownBy(closeable::close)
        .isInstanceOf(RuntimeException.class)
        .hasMessage("Cancel failed");
    verify(mockFuture).cancel(true);
  }

  @Test
  void cancelOnCloseWithCancelledFuture() {
    CompletableFuture<String> future = new CompletableFuture<>();
    future.cancel(true);
    UncheckedAutoCloseable closeable = AutoCloseables.cancelOnClose(future);
    assertThatCode(closeable::close).doesNotThrowAnyException();
    assertThat(future.isDone()).isTrue();
    assertThat(future.isCancelled()).isTrue();
    assertThat(future.isCompletedExceptionally()).isTrue();
  }
}

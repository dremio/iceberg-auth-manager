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
import static org.mockito.Mockito.when;

import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

class FuturesTest {

  @Test
  void getNow() {
    assertThat((Object) Futures.getNow(null)).isNull();
    assertThat(Futures.getNow(CompletableFuture.completedFuture("value"))).isEqualTo("value");
    assertThat((Object) Futures.getNow(CompletableFuture.completedFuture(null))).isNull();
    // failed future
    CompletableFuture<Object> failed = CompletableFuture.failedFuture(new Exception("test"));
    assertThat(Futures.getNow(failed)).isNull();
    // cancelled future
    CompletableFuture<Object> cancelled = new CompletableFuture<>();
    cancelled.cancel(true);
    assertThat(Futures.getNow(cancelled)).isNull();
  }

  @Test
  void cancelFuture() {
    assertThatCode(() -> Futures.cancel(null)).doesNotThrowAnyException();
    CompletableFuture<?> future = new CompletableFuture<>();
    Futures.cancel(future);
    assertThat(future.isDone()).isTrue();
    assertThat(future.isCancelled()).isTrue();
    assertThat(future.isCompletedExceptionally()).isTrue();
  }

  @Test
  void cancelFutureWithException() {
    CompletableFuture<?> future = mock(CompletableFuture.class);
    when(future.cancel(true)).thenThrow(new RuntimeException("test"));
    assertThatThrownBy(() -> Futures.cancel(future))
        .isInstanceOf(RuntimeException.class)
        .hasMessage("test");
  }
}

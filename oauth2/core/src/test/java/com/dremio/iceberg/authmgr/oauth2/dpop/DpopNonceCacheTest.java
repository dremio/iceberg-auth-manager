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
package com.dremio.iceberg.authmgr.oauth2.dpop;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.openid.connect.sdk.Nonce;
import org.junit.jupiter.api.Test;

class DpopNonceCacheTest {

  private static final Nonce N_AS_1 = new Nonce("n-as-1");
  private static final Nonce N_AS_2 = new Nonce("n-as-2");
  private static final Nonce N_RS_1 = new Nonce("n-rs-1");

  @Test
  void testGetBeforePutIsEmpty() {
    DpopNonceCache cache = new DpopNonceCache();
    assertThat(cache.get(DpopScope.AS)).isEmpty();
    assertThat(cache.get(DpopScope.RS)).isEmpty();
  }

  @Test
  void testPutThenGet() {
    DpopNonceCache cache = new DpopNonceCache();
    cache.put(DpopScope.AS, N_AS_1);
    assertThat(cache.get(DpopScope.AS)).hasValue(N_AS_1);
  }

  @Test
  void testScopesAreIsolated() {
    DpopNonceCache cache = new DpopNonceCache();
    cache.put(DpopScope.AS, N_AS_1);
    cache.put(DpopScope.RS, N_RS_1);

    assertThat(cache.get(DpopScope.AS)).hasValue(N_AS_1);
    assertThat(cache.get(DpopScope.RS)).hasValue(N_RS_1);
  }

  @Test
  void testLastWriteWins() {
    DpopNonceCache cache = new DpopNonceCache();
    cache.put(DpopScope.AS, N_AS_1);
    cache.put(DpopScope.AS, N_AS_2);
    assertThat(cache.get(DpopScope.AS)).hasValue(N_AS_2);
  }

  @Test
  void testCopyInheritsEntriesThenDiverges() {
    DpopNonceCache original = new DpopNonceCache();
    original.put(DpopScope.AS, N_AS_1);
    original.put(DpopScope.RS, N_RS_1);

    DpopNonceCache copy = original.copy();
    assertThat(copy.get(DpopScope.AS)).hasValue(N_AS_1);
    assertThat(copy.get(DpopScope.RS)).hasValue(N_RS_1);

    copy.put(DpopScope.AS, N_AS_2);
    assertThat(copy.get(DpopScope.AS)).hasValue(N_AS_2);
    assertThat(original.get(DpopScope.AS)).hasValue(N_AS_1);
  }
}

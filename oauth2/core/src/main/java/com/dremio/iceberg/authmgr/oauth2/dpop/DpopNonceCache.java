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

import com.nimbusds.openid.connect.sdk.Nonce;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Per-scope cache for the most recently observed {@code DPoP-Nonce} value.
 *
 * <p>RFC 9449 §8 lets the authorization server or the resource server require the client to include
 * a {@code nonce} claim in its DPoP proofs, supplying the current value via a {@code DPoP-Nonce}
 * response header. Nonces are issuer-scoped — an AS nonce is not interchangeable with an RS nonce
 * even when the two servers share an origin — so the cache is keyed by {@link DpopScope}. Per RFC,
 * only the most recent nonce per issuer matters, so the cache holds at most one entry per scope
 * (two in total).
 */
public final class DpopNonceCache {

  private final ConcurrentMap<DpopScope, Nonce> byScope;

  public DpopNonceCache() {
    byScope = new ConcurrentHashMap<>();
  }

  private DpopNonceCache(DpopNonceCache toCopy) {
    byScope = new ConcurrentHashMap<>(toCopy.byScope);
  }

  /** Returns the most recently observed nonce for the given scope, if any. */
  public Optional<Nonce> get(DpopScope scope) {
    return Optional.ofNullable(byScope.get(Objects.requireNonNull(scope, "scope")));
  }

  /** Stores {@code nonce} for the given scope, overwriting any prior value. */
  public void put(DpopScope scope, Nonce nonce) {
    byScope.put(Objects.requireNonNull(scope, "scope"), Objects.requireNonNull(nonce, "nonce"));
  }

  /**
   * Returns a new cache pre-populated with this cache's current entries. Subsequent mutations on
   * either cache are independent.
   */
  public DpopNonceCache copy() {
    return new DpopNonceCache(this);
  }
}

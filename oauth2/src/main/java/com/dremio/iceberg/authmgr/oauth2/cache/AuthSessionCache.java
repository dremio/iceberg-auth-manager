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
package com.dremio.iceberg.authmgr.oauth2.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.util.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// This is a copy of https://github.com/apache/iceberg/pull/12562
// TODO remove this class once the PR is merged

/** A cache for {@link AuthSession} instances. */
public class AuthSessionCache<K, V extends AuthSession> implements AutoCloseable {

  private static final Logger LOG = LoggerFactory.getLogger(AuthSessionCache.class);

  private final Duration sessionTimeout;
  private final Executor executor;
  private final Ticker ticker;

  private volatile Cache<K, V> sessionCache;

  /**
   * Creates a new cache with the given session timeout, and with default executor and default
   * ticker for eviction tasks.
   *
   * @param name a distinctive name for the cache.
   * @param sessionTimeout the session timeout. Sessions will become eligible for eviction after
   *     this duration of inactivity.
   */
  public AuthSessionCache(String name, Duration sessionTimeout) {
    this(
        sessionTimeout,
        ThreadPools.newExitingWorkerPool(name + "-auth-session-evict", 1),
        Ticker.systemTicker());
  }

  /**
   * Creates a new cache with the given session timeout, executor, and ticker. This method is useful
   * for testing mostly.
   *
   * @param sessionTimeout the session timeout. Sessions will become eligible for eviction after
   *     this duration of inactivity.
   * @param executor the executor to use for eviction tasks; if null, the cache will create a
   *     default executor. The executor will be closed when this cache is closed.
   * @param ticker the ticker to use for the cache.
   */
  AuthSessionCache(Duration sessionTimeout, Executor executor, Ticker ticker) {
    this.sessionTimeout = sessionTimeout;
    this.executor = executor;
    this.ticker = ticker;
  }

  /**
   * Returns a cached session for the given key, loading it with the given loader if it is not
   * already cached.
   *
   * @param key the key to use for the session.
   * @param loader the loader to use to load the session if it is not already cached.
   * @return the cached session.
   */
  public V cachedSession(K key, Function<K, V> loader) {
    return sessionCache().get(key, loader);
  }

  @Override
  public void close() {
    try {
      Cache<K, V> cache = sessionCache;
      this.sessionCache = null;
      if (cache != null) {
        cache.invalidateAll();
        cache.cleanUp();
      }
    } finally {
      if (executor instanceof ExecutorService) {
        ExecutorService service = (ExecutorService) executor;
        service.shutdown();
        try {
          if (!service.awaitTermination(10, TimeUnit.SECONDS)) {
            LOG.warn("Timed out waiting for eviction executor to terminate");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
        service.shutdownNow();
      }
    }
  }

  Cache<K, V> sessionCache() {
    if (sessionCache == null) {
      synchronized (this) {
        if (sessionCache == null) {
          this.sessionCache = newSessionCache();
        }
      }
    }

    return sessionCache;
  }

  private Cache<K, V> newSessionCache() {
    Caffeine<K, V> builder =
        Caffeine.newBuilder()
            .executor(executor)
            .expireAfterAccess(sessionTimeout)
            .ticker(ticker)
            .removalListener(
                (id, auth, cause) -> {
                  if (auth != null) {
                    auth.close();
                  }
                });

    return builder.build();
  }
}

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
package com.dremio.iceberg.authmgr.oauth2;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthManager;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.rest.auth.AuthSessionCache;
import org.apache.iceberg.util.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuth2Manager implements AuthManager {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Manager.class);

  private final String name;

  private OAuth2Session initSession;
  private ScheduledExecutorService refreshExecutor;

  private volatile AuthSessionCache sessionCache;

  public OAuth2Manager(String managerName) {
    this.name = managerName;
  }

  @Override
  public AuthSession initSession(RESTClient initClient, Map<String, String> initProperties) {
    return initSession = new OAuth2Session(initProperties, refreshExecutor());
  }

  @Override
  public AuthSession catalogSession(
      RESTClient sharedClient, Map<String, String> catalogProperties) {
    // Copy the existing session if the properties are the same as the init session
    // to avoid requiring from users to log in again, for human-based flows.
    OAuth2Session catalogSession =
        initSession != null && catalogProperties.equals(initSession.getProperties())
            ? initSession.copy()
            : new OAuth2Session(catalogProperties, refreshExecutor());
    initSession = null; // already closed
    return catalogSession;
  }

  @Override
  public AuthSession contextualSession(SessionContext context, AuthSession parent) {
    if ((context.properties() == null || context.properties().isEmpty())
        && (context.credentials() == null || context.credentials().isEmpty())) {
      return parent;
    }
    Map<String, String> contextProperties =
        RESTUtil.merge(
            Optional.ofNullable(context.properties()).orElseGet(Map::of),
            Optional.ofNullable(context.credentials()).orElseGet(Map::of));
    Map<String, String> parentProperties = ((OAuth2Session) parent).getProperties();
    Map<String, String> childProperties = RESTUtil.merge(parentProperties, contextProperties);
    if (childProperties.equals(parentProperties)) {
      return parent;
    }
    AuthSessionCache cache = getOrCreateSessionCache(parentProperties);
    return cache.cachedSession(
        context.sessionId(), id -> new OAuth2Session(childProperties, refreshExecutor()));
  }

  @Override
  public AuthSession tableSession(RESTClient sharedClient, Map<String, String> properties) {
    // Note: this method is invoked only from the S3 signer client.
    // A signer client can interact with more than one signing endpoint, but there should never be
    // more than one auth session per signing endpoint, so use that as the session key.
    // Note: as per S3V4RestSignerClient, either 's3.signer.uri' or 'uri' must be set.
    String key = properties.getOrDefault("s3.signer.uri", properties.get(CatalogProperties.URI));
    AuthSessionCache cache = getOrCreateSessionCache(properties);
    return cache.cachedSession(key, k -> new OAuth2Session(properties, refreshExecutor()));
  }

  @Override
  public void close() {
    AuthSession session = initSession;
    AuthSessionCache cache = sessionCache;
    try (session;
        cache) {
      ScheduledExecutorService executor = this.refreshExecutor;
      if (executor != null) { // Iceberg < 1.10 only
        executor.shutdown();
        try {
          if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
            LOGGER.warn("Timed out waiting for refresh executor to terminate");
            executor.shutdownNow();
          }
        } catch (InterruptedException e) {
          LOGGER.warn("Interrupted while waiting for refresh executor to terminate", e);
          Thread.currentThread().interrupt();
        }
      }
    } finally {
      this.initSession = null;
      this.sessionCache = null;
      this.refreshExecutor = null;
    }
  }

  private ScheduledExecutorService refreshExecutor() {
    if (refreshExecutor != null) {
      return refreshExecutor;
    }
    try {
      return ThreadPools.authRefreshPool();
    } catch (NoSuchMethodError e) {
      // Iceberg < 1.10 doesn't have ThreadPools.authRefreshPool()
      return refreshExecutor = ThreadPools.newScheduledPool(name + "-token-refresh", 1);
    }
  }

  private AuthSessionCache getOrCreateSessionCache(Map<String, String> properties) {
    AuthSessionCache cache = sessionCache;
    if (cache == null) {
      synchronized (this) {
        if (sessionCache == null) {
          OAuth2Config config = OAuth2Config.from(properties);
          cache = new AuthSessionCache(name, config.getSystemConfig().getSessionCacheTimeout());
          sessionCache = cache;
        }
      }
    }
    return cache;
  }
}

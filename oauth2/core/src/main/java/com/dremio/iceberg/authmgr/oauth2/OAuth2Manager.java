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

import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCache;
import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCacheFactory;
import com.dremio.iceberg.authmgr.oauth2.config.ConfigSanitizer;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthManager;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.util.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuth2Manager implements AuthManager {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Manager.class);

  private final String name;
  private final AuthSessionCacheFactory<OAuth2Config, OAuth2Session> sessionCacheFactory;

  private final ConfigSanitizer configSanitizer = new ConfigSanitizer();

  private OAuth2Session initSession;
  private AuthSessionCache<OAuth2Config, OAuth2Session> sessionCache;
  private ScheduledExecutorService refreshExecutor;

  public OAuth2Manager(String managerName) {
    this(managerName, OAuth2Manager::createSessionCache);
  }

  public OAuth2Manager(
      String managerName,
      AuthSessionCacheFactory<OAuth2Config, OAuth2Session> sessionCacheFactory) {
    this.name = managerName;
    this.sessionCacheFactory = sessionCacheFactory;
  }

  @Override
  public AuthSession initSession(RESTClient initClient, Map<String, String> initProperties) {
    OAuth2Config initConfig = OAuth2Config.from(initProperties);
    initialize(initConfig);
    return initSession = new OAuth2Session(initProperties, initConfig, refreshExecutor());
  }

  @Override
  public AuthSession catalogSession(
      RESTClient sharedClient, Map<String, String> catalogProperties) {
    OAuth2Config catalogConfig = OAuth2Config.from(catalogProperties);
    initialize(catalogConfig);
    OAuth2Session catalogSession;
    if (initSession != null && catalogProperties.equals(initSession.getProperties())) {
      // Copy the existing session if the properties are the same as the init session
      // to avoid requiring from users to log in again, for human-based flows.
      catalogSession = initSession.copy();
    } else {
      catalogSession = new OAuth2Session(catalogProperties, catalogConfig, refreshExecutor());
    }
    initSession = null;
    return catalogSession;
  }

  @Override
  public AuthSession contextualSession(SessionContext context, AuthSession parent) {
    Map<String, String> contextProperties =
        RESTUtil.merge(
            Optional.ofNullable(context.properties()).orElseGet(Map::of),
            Optional.ofNullable(context.credentials()).orElseGet(Map::of));
    contextProperties = configSanitizer.sanitizeContextProperties(contextProperties);
    return maybeCacheSession(parent, contextProperties);
  }

  @Override
  public AuthSession tableSession(
      TableIdentifier table, Map<String, String> properties, AuthSession parent) {
    Map<String, String> tableProperties = configSanitizer.sanitizeTableProperties(properties);
    return maybeCacheSession(parent, tableProperties);
  }

  private AuthSession maybeCacheSession(AuthSession parent, Map<String, String> childProperties) {
    Map<String, String> parentProperties = ((OAuth2Session) parent).getProperties();
    Map<String, String> mergedProperties = RESTUtil.merge(parentProperties, childProperties);
    if (mergedProperties.equals(parentProperties)) {
      return parent;
    }
    return sessionCache.cachedSession(
        OAuth2Config.from(mergedProperties),
        cfg -> new OAuth2Session(mergedProperties, cfg, refreshExecutor()));
  }

  @Override
  public AuthSession tableSession(RESTClient sharedClient, Map<String, String> properties) {
    // Do NOT sanitize table properties, as they may contain credentials coming from the
    // catalog properties.
    OAuth2Config config = OAuth2Config.from(properties);
    initialize(config);
    return sessionCache.cachedSession(
        config, cfg -> new OAuth2Session(properties, cfg, refreshExecutor()));
  }

  @Override
  public void close() {
    AuthSession session = initSession;
    AuthSessionCache<OAuth2Config, OAuth2Session> cache = sessionCache;
    try (session;
        cache) {
      ScheduledExecutorService executor = this.refreshExecutor;
      if (executor != null) {
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

  private void initialize(OAuth2Config config) {
    if (sessionCache == null) {
      sessionCache = sessionCacheFactory.apply(name, config);
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

  private static AuthSessionCache<OAuth2Config, OAuth2Session> createSessionCache(
      String name, OAuth2Config config) {
    return new AuthSessionCache<>(name, config.getSystemConfig().getSessionCacheTimeout());
  }
}

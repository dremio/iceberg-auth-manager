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
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.rest.auth.RefreshingAuthManager;

public class OAuth2Manager extends RefreshingAuthManager {

  private final String name;
  private final AuthSessionCacheFactory<OAuth2Config, OAuth2Session> sessionCacheFactory;

  private final ConfigSanitizer configSanitizer = new ConfigSanitizer();

  private OAuth2Session initSession;
  private AuthSessionCache<OAuth2Config, OAuth2Session> sessionCache;

  public OAuth2Manager(String managerName) {
    this(managerName, OAuth2Manager::createSessionCache);
  }

  public OAuth2Manager(
      String managerName,
      AuthSessionCacheFactory<OAuth2Config, OAuth2Session> sessionCacheFactory) {
    super(managerName + "-token-refresh");
    this.name = managerName;
    this.sessionCacheFactory = sessionCacheFactory;
  }

  @Override
  public AuthSession initSession(RESTClient initClient, Map<String, String> initProperties) {
    OAuth2Config initConfig = OAuth2Config.from(initProperties);
    initialize(initConfig);
    return initSession = new OAuth2Session(initConfig, refreshExecutor());
  }

  @Override
  public AuthSession catalogSession(
      RESTClient sharedClient, Map<String, String> catalogProperties) {
    OAuth2Config catalogConfig = OAuth2Config.from(catalogProperties);
    initialize(catalogConfig);
    OAuth2Session catalogSession;
    if (initSession != null && catalogConfig.equals(initSession.getConfig())) {
      // Copy the existing session if the properties are the same as the init session
      // to avoid requiring from users to log in again, for human-based flows.
      catalogSession = initSession.copy();
    } else {
      catalogSession = new OAuth2Session(catalogConfig, refreshExecutor());
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
    OAuth2Config parentConfig = ((OAuth2Session) parent).getConfig();
    OAuth2Config childConfig = parentConfig.merge(childProperties);
    return childConfig.equals(parentConfig)
        ? parent
        : sessionCache.cachedSession(
            childConfig, k -> new OAuth2Session(childConfig, refreshExecutor()));
  }

  @Override
  public AuthSession tableSession(RESTClient sharedClient, Map<String, String> properties) {
    // Do NOT sanitize table properties, as they may contain credentials coming from the
    // catalog properties.
    OAuth2Config config = OAuth2Config.from(properties);
    initialize(config);
    return sessionCache.cachedSession(config, k -> new OAuth2Session(config, refreshExecutor()));
  }

  @Override
  public void close() {
    AuthSession session = initSession;
    AuthSessionCache<OAuth2Config, OAuth2Session> cache = sessionCache;
    try (session;
        cache) {
      super.close();
    } finally {
      this.initSession = null;
      this.sessionCache = null;
    }
  }

  private void initialize(OAuth2Config config) {
    if (sessionCache == null) {
      sessionCache = sessionCacheFactory.apply(name, config);
    }
  }

  private static AuthSessionCache<OAuth2Config, OAuth2Session> createSessionCache(
      String name, OAuth2Config config) {
    return new AuthSessionCache<>(name, config.getSystemConfig().getSessionCacheTimeout());
  }
}

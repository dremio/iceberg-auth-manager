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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCache;
import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCacheFactory;
import com.dremio.iceberg.authmgr.oauth2.compat.IcebergCompatibility;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.rest.auth.RefreshingAuthManager;

public class OAuth2Manager extends RefreshingAuthManager {

  private final String name;
  private final AuthSessionCacheFactory<OAuth2AgentSpec, OAuth2Session> sessionCacheFactory;

  private OAuth2Session initSession;
  private RESTClient client;
  private AuthSessionCache<OAuth2AgentSpec, OAuth2Session> sessionCache;

  public OAuth2Manager(String managerName) {
    this(managerName, OAuth2Manager::createSessionCache);
  }

  public OAuth2Manager(
      String managerName,
      AuthSessionCacheFactory<OAuth2AgentSpec, OAuth2Session> sessionCacheFactory) {
    super(managerName + "-token-refresh");
    this.name = managerName;
    this.sessionCacheFactory = sessionCacheFactory;
  }

  @Override
  public AuthSession initSession(RESTClient initClient, Map<String, String> initProperties) {
    initProperties = IcebergCompatibility.migrate(initProperties);
    OAuth2AgentSpec initSpec = OAuth2AgentSpec.builder().from(initProperties).build();
    initClient = initClient.withAuthSession(AuthSession.EMPTY);
    initSession = new OAuth2Session(initSpec, refreshExecutor(), initClient);
    return new UncloseableAuthSession(initSession);
  }

  @Override
  public AuthSession catalogSession(
      RESTClient sharedClient, Map<String, String> catalogProperties) {
    client = sharedClient.withAuthSession(AuthSession.EMPTY);
    catalogProperties = IcebergCompatibility.migrate(catalogProperties);
    OAuth2AgentSpec catalogSpec = OAuth2AgentSpec.builder().from(catalogProperties).build();
    sessionCache = sessionCacheFactory.apply(name, catalogProperties);
    OAuth2Session catalogSession;
    if (initSession != null && catalogSpec.equals(initSession.getSpec())) {
      // Avoid creating a new session if the properties are the same as the init session
      // as this would require users to log in again, for human-based flows.
      catalogSession = initSession;
      catalogSession.updateRestClient(client);
    } else {
      catalogSession = new OAuth2Session(catalogSpec, refreshExecutor(), client);
      if (initSession != null) {
        initSession.close();
      }
    }
    initSession = null;
    return catalogSession;
  }

  @Override
  public AuthSession contextualSession(SessionContext context, AuthSession parent) {
    Map<String, String> contextProperties =
        IcebergCompatibility.migrate(
            RESTUtil.merge(
                Optional.ofNullable(context.properties()).orElseGet(Map::of),
                Optional.ofNullable(context.credentials()).orElseGet(Map::of)));
    OAuth2AgentSpec parentSpec = ((OAuth2Session) parent).getSpec();
    OAuth2AgentSpec childSpec = parentSpec.merge(contextProperties);
    if (!childSpec.equals(parentSpec)) {
      return sessionCache.cachedSession(
          childSpec, k -> new OAuth2Session(childSpec, refreshExecutor(), client));
    }
    return parent;
  }

  @Override
  public AuthSession tableSession(
      TableIdentifier table, Map<String, String> properties, AuthSession parent) {
    Map<String, String> tableProperties =
        IcebergCompatibility.migrate(IcebergCompatibility.sanitizeFromServer(properties));
    OAuth2AgentSpec parentSpec = ((OAuth2Session) parent).getSpec();
    OAuth2AgentSpec childSpec = parentSpec.merge(tableProperties);
    if (!childSpec.equals(parentSpec)) {
      return sessionCache.cachedSession(
          childSpec, k -> new OAuth2Session(childSpec, refreshExecutor(), client));
    }
    return parent;
  }

  @Override
  public void close() {
    AuthSession session = initSession;
    AuthSessionCache<OAuth2AgentSpec, OAuth2Session> cache = sessionCache;
    try (session;
        cache) {
      super.close();
    } finally {
      this.initSession = null;
      this.sessionCache = null;
      this.client = null;
    }
  }

  private static AuthSessionCache<OAuth2AgentSpec, OAuth2Session> createSessionCache(
      String name, Map<String, String> properties) {
    return new AuthSessionCache<>(
        name,
        Duration.parse(
            properties.getOrDefault(
                OAuth2Properties.Runtime.SESSION_CACHE_TIMEOUT,
                OAuth2Properties.Runtime.DEFAULT_SESSION_CACHE_TIMEOUT)));
  }

  private static class UncloseableAuthSession implements AuthSession {

    private final AuthSession delegate;

    UncloseableAuthSession(AuthSession delegate) {
      this.delegate = delegate;
    }

    @Override
    public HTTPRequest authenticate(HTTPRequest request) {
      return delegate.authenticate(request);
    }

    @Override
    public void close() {
      // Do nothing
    }
  }
}

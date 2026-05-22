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
package com.dremio.iceberg.authmgr.oauth2.core;

import static com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentConfig.PREFIX;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.agent.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.agent.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.agent.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.agent.config.SystemConfig;
import com.dremio.iceberg.authmgr.oauth2.agent.user.UserEmulator;
import com.dremio.iceberg.authmgr.oauth2.core.expectation.ImmutableConfigEndpointExpectation;
import com.dremio.iceberg.authmgr.oauth2.core.expectation.ImmutableLoadTableEndpointExpectation;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import com.google.errorprone.annotations.MustBeClosed;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.UUID;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.catalog.SessionCatalog;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.RESTCatalog;
import org.apache.iceberg.rest.ResourcePaths;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.AuthSession;
import org.immutables.value.Value;

@AuthManagerImmutable
@Value.Immutable(copy = false)
@SuppressWarnings("immutables:subtype")
public abstract class IcebergTestEnvironment extends TestEnvironment {

  public static final TableIdentifier TABLE_IDENTIFIER = TableIdentifier.of("namespace1", "table1");

  public static final SessionCatalog.SessionContext SESSION_CONTEXT =
      new SessionCatalog.SessionContext(
          UUID.randomUUID().toString(),
          "user",
          Map.of(
              PREFIX + '.' + BasicConfig.CLIENT_ID,
              TestConstants.CLIENT_ID2.getValue(),
              PREFIX + '.' + BasicConfig.CLIENT_SECRET,
              TestConstants.CLIENT_SECRET2.getValue()),
          Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE2.toString()));

  @Value.Default
  public SessionCatalog.SessionContext getSessionContext() {
    return SessionCatalog.SessionContext.createEmpty();
  }

  @Value.Default
  public URI getLoadTableEndpoint() {
    return getCatalogServerUrl()
        .resolve(
            ResourcePaths.forCatalogProperties(getCatalogProperties()).table(TABLE_IDENTIFIER));
  }

  @Value.Default
  public Map<String, String> getCatalogProperties() {
    return ImmutableMap.<String, String>builder()
        .put(CatalogProperties.URI, getCatalogServerUrl().toString())
        .put("prefix", TestConstants.WAREHOUSE)
        .put(CatalogProperties.FILE_IO_IMPL, "org.apache.iceberg.inmemory.InMemoryFileIO")
        .put(AuthProperties.AUTH_TYPE, OAuth2Manager.class.getName())
        .put(PREFIX + '.' + BasicConfig.GRANT_TYPE, getGrantType().toString())
        .put(PREFIX + '.' + BasicConfig.ISSUER_URL, getAuthorizationServerUrl().toString())
        .put(PREFIX + '.' + BasicConfig.CLIENT_ID, getClientId().getValue())
        .put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, getClientSecret().getValue())
        .put(PREFIX + '.' + BasicConfig.SCOPE, getScope().toString())
        .put(PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1", "value1")
        .put(SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getAgentName())
        .build();
  }

  public HTTPClient.Builder newIcebergRestClientBuilder(Map<String, String> properties) {
    return HTTPClient.builder(properties)
        .uri(getCatalogServerUrl())
        .withAuthSession(AuthSession.EMPTY);
  }

  @MustBeClosed
  public RESTCatalog newCatalog() {
    RESTCatalog catalog =
        new RESTCatalog(getSessionContext(), config -> newIcebergRestClientBuilder(config).build());
    UserEmulator user = getUser();
    user.addErrorListener(
        e -> {
          try {
            catalog.close();
          } catch (IOException ex) {
            throw new RuntimeException(ex);
          }
        });
    catalog.initialize("catalog-" + java.lang.System.nanoTime(), getCatalogProperties());
    return catalog;
  }

  @Override
  public void createOtherExpectations() {
    ImmutableConfigEndpointExpectation.of(this).create();
    ImmutableLoadTableEndpointExpectation.of(this).create();
  }
}

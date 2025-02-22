/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE3;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SESSION_CONTEXT;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.TABLE_IDENTIFIER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.github.benmanes.caffeine.cache.Cache;
import java.io.IOException;
import java.util.Map;
import org.apache.iceberg.Table;
import org.apache.iceberg.rest.RESTCatalog;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.MapAssert;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class OAuth2ManagerCatalogTest {

  private static final String SESSION_CACHE =
      "sessionCatalog.authManager.sessionCache.sessionCache";
  private static final String CATALOG_SPEC = "sessionCatalog.catalogAuth.spec";

  @ParameterizedTest
  @EnumSource(Dialect.class)
  void testCatalogProperties(Dialect dialect) throws IOException {
    try (TestEnvironment env = TestEnvironment.builder().dialect(dialect).build();
        RESTCatalog catalog = env.newCatalog()) {
      Table table = catalog.loadTable(TABLE_IDENTIFIER);
      assertThat(table).isNotNull();
      assertThat(table.name()).isEqualTo(catalog.name() + "." + TABLE_IDENTIFIER);
      assertThat(catalog)
          .extracting(CATALOG_SPEC, type(OAuth2AgentSpec.class))
          .satisfies(spec -> assertSpec(spec, CLIENT_ID1, CLIENT_SECRET1, SCOPE1));
      assertThat(catalog).extracting(SESSION_CACHE).isNull();
    }
  }

  @ParameterizedTest
  @EnumSource(Dialect.class)
  void testCatalogAndSessionProperties(Dialect dialect) throws IOException {
    try (TestEnvironment env =
            TestEnvironment.builder().dialect(dialect).sessionContext(SESSION_CONTEXT).build();
        RESTCatalog catalog = env.newCatalog()) {
      Table table = catalog.loadTable(TABLE_IDENTIFIER);
      assertThat(table).isNotNull();
      assertThat(table.name()).isEqualTo(catalog.name() + "." + TABLE_IDENTIFIER);
      assertThat(catalog)
          .extracting(CATALOG_SPEC, type(OAuth2AgentSpec.class))
          .satisfies(spec -> assertSpec(spec, CLIENT_ID1, CLIENT_SECRET1, SCOPE1));
      assertThat(catalog)
          .extracting(SESSION_CACHE, asMap())
          .satisfies(
              cache -> {
                assertThat(cache).hasSize(1);
                OAuth2AgentSpec spec = cache.keySet().iterator().next();
                assertSpec(spec, CLIENT_ID2, CLIENT_SECRET2, SCOPE2);
              });
    }
  }

  @ParameterizedTest
  @EnumSource(Dialect.class)
  void testCatalogAndTableProperties(Dialect dialect) throws IOException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dialect(dialect)
                .tableProperties(Map.of(Basic.SCOPE, SCOPE2))
                .build();
        RESTCatalog catalog = env.newCatalog()) {
      Table table = catalog.loadTable(TABLE_IDENTIFIER);
      assertThat(table).isNotNull();
      assertThat(table.name()).isEqualTo(catalog.name() + "." + TABLE_IDENTIFIER);
      assertThat(catalog)
          .extracting(CATALOG_SPEC, type(OAuth2AgentSpec.class))
          .satisfies(spec -> assertSpec(spec, CLIENT_ID1, CLIENT_SECRET1, SCOPE1));
      assertThat(catalog)
          .extracting(SESSION_CACHE, asMap())
          .satisfies(
              cache -> {
                assertThat(cache).hasSize(1);
                OAuth2AgentSpec spec = cache.keySet().iterator().next();
                // client id and secret from the catalog properties, scope from the table properties
                assertSpec(spec, CLIENT_ID1, CLIENT_SECRET1, SCOPE2);
              });
    }
  }

  @ParameterizedTest
  @EnumSource(Dialect.class)
  void testCatalogAndSessionAndTableProperties(Dialect dialect) throws IOException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dialect(dialect)
                .sessionContext(SESSION_CONTEXT)
                .tableProperties(Map.of(Basic.SCOPE, SCOPE3))
                .build();
        RESTCatalog catalog = env.newCatalog()) {
      Table table = catalog.loadTable(TABLE_IDENTIFIER);
      assertThat(table).isNotNull();
      assertThat(table.name()).isEqualTo(catalog.name() + "." + TABLE_IDENTIFIER);
      assertThat(catalog)
          .extracting(CATALOG_SPEC, type(OAuth2AgentSpec.class))
          .satisfies(spec -> assertSpec(spec, CLIENT_ID1, CLIENT_SECRET1, SCOPE1));
      assertThat(catalog)
          .extracting(SESSION_CACHE, asMap())
          .satisfies(
              cache ->
                  assertThat(cache)
                      .hasSize(2)
                      // context session
                      .anySatisfy(
                          (spec, session) -> assertSpec(spec, CLIENT_ID2, CLIENT_SECRET2, SCOPE2))
                      // table session
                      // client id and secret from the context session, scope from the table
                      // properties
                      .anySatisfy(
                          (spec, session) -> assertSpec(spec, CLIENT_ID2, CLIENT_SECRET2, SCOPE3)));
    }
  }

  private static void assertSpec(
      OAuth2AgentSpec spec, String clientId, String clientSecret, String scope) {
    assertThat(spec).isNotNull();
    assertThat(spec.getBasicConfig().getClientId()).contains(clientId);
    assertThat(spec.getBasicConfig().getClientSecret()).contains(Secret.of(clientSecret));
    assertThat(spec.getBasicConfig().getScopes()).containsOnly(scope);
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static InstanceOfAssertFactory<Cache, MapAssert<OAuth2AgentSpec, OAuth2Session>> asMap() {
    return new InstanceOfAssertFactory<Cache, MapAssert<OAuth2AgentSpec, OAuth2Session>>(
        Cache.class,
        new Class[] {OAuth2AgentSpec.class, OAuth2Session.class},
        actual -> Assertions.assertThat(actual.asMap()));
  }
}

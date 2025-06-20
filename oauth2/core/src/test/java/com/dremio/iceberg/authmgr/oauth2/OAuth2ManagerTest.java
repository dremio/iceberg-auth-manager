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
import static org.mockito.Mockito.never;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Manager;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCache;
import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.github.benmanes.caffeine.cache.Cache;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;
import org.apache.iceberg.Table;
import org.apache.iceberg.catalog.SessionCatalog;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.HTTPHeaders.HTTPHeader;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.HTTPRequest.HTTPMethod;
import org.apache.iceberg.rest.ImmutableHTTPRequest;
import org.apache.iceberg.rest.RESTCatalog;
import org.apache.iceberg.rest.ResourcePaths;
import org.apache.iceberg.rest.auth.AuthSession;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.MapAssert;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

class OAuth2ManagerTest {

  @Nested
  class UnitTests {

    private final TableIdentifier table = TableIdentifier.of("t1");

    private final HTTPRequest request =
        ImmutableHTTPRequest.builder()
            .baseUri(URI.create("http://localhost:8181"))
            .method(HTTPMethod.GET)
            .path("v1/config")
            .build();

    @Test
    void catalogSessionWithoutInit() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        try (AuthSession session = manager.catalogSession(env.getHttpClient(), properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void catalogSessionWithInit() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        try (HTTPClient httpClient = env.newHttpClientBuilder(Map.of()).build();
            AuthSession session = manager.initSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
        try (HTTPClient httpClient = env.newHttpClientBuilder(Map.of()).build();
            AuthSession session = manager.catalogSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void catalogSessionWithInitAndIcebergRestDialect() throws IOException {
      try (TestEnvironment env =
              TestEnvironment.builder()
                  .dialect(Dialect.ICEBERG_REST)
                  .tokenEndpoint(URI.create(ResourcePaths.tokens()))
                  .build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                Basic.DIALECT,
                Dialect.ICEBERG_REST.name(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        try (HTTPClient httpClient = env.newHttpClientBuilder(Map.of()).build();
            AuthSession session = manager.initSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
        try (HTTPClient httpClient = env.newHttpClientBuilder(Map.of()).build();
            AuthSession session = manager.catalogSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void contextualSessionEmptyContext() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);
        SessionCatalog.SessionContext context = SessionCatalog.SessionContext.createEmpty();
        try (AuthSession catalogSession = manager.catalogSession(env.getHttpClient(), properties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void contextualSessionIdenticalSpec() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);
        SessionCatalog.SessionContext context =
            new SessionCatalog.SessionContext(
                "test",
                "test",
                properties,
                Map.of(OAuth2Properties.Basic.SCOPE, TestConstants.SCOPE1));
        try (AuthSession catalogSession = manager.catalogSession(env.getHttpClient(), properties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void contextualSessionDifferentSpec() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    Basic.CLIENT_ID,
                    TestConstants.CLIENT_ID2,
                    Basic.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2),
                Map.of(
                    Basic.SCOPE,
                    TestConstants.SCOPE2,
                    Basic.EXTRA_PARAMS_PREFIX + "extra2",
                    "value2"));
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isNotSameAs(catalogSession);
          HTTPRequest actual = contextualSession.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void contextualSessionDifferentSpecLegacyProperties() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Manager.MIGRATE_LEGACY_PROPERTIES,
                "true",
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    org.apache.iceberg.rest.auth.OAuth2Properties.CREDENTIAL,
                    TestConstants.CLIENT_ID2 + ":" + TestConstants.CLIENT_SECRET2),
                Map.of(org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE, TestConstants.SCOPE2));
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isNotSameAs(catalogSession);
          HTTPRequest actual = contextualSession.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void contextualSessionCacheHit() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);
        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    Basic.CLIENT_ID,
                    TestConstants.CLIENT_ID2,
                    Basic.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2,
                    TokenExchange.SUBJECT_TOKEN,
                    TestConstants.SUBJECT_TOKEN,
                    TokenExchange.ACTOR_TOKEN,
                    TestConstants.ACTOR_TOKEN),
                Map.of(
                    Basic.GRANT_TYPE,
                    GrantType.TOKEN_EXCHANGE.name(),
                    Basic.SCOPE,
                    TestConstants.SCOPE2));
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession contextualSession1 = manager.contextualSession(context, catalogSession);
            AuthSession contextualSession2 = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession1).isNotSameAs(catalogSession);
          assertThat(contextualSession2).isNotSameAs(catalogSession);
          assertThat(contextualSession1).isSameAs(contextualSession2);
        }
      }
    }

    @Test
    void tableSessionEmptyConfig() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);
        Map<String, String> tableProperties = Map.of();
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void tableSessionIdenticalSpec() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);
        Map<String, String> tableProperties = Map.of(Basic.SCOPE, TestConstants.SCOPE1);
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void tableSessionDifferentSpec() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        Map<String, String> tableProperties =
            Map.of(
                Basic.SCOPE, TestConstants.SCOPE2, Basic.EXTRA_PARAMS_PREFIX + "extra2", "value2");
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isNotSameAs(catalogSession);
          HTTPRequest actual = tableSession.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void tableSessionDifferentSpecLegacyProperties() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Manager.MIGRATE_LEGACY_PROPERTIES,
                "true",
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        Map<String, String> tableProperties =
            Map.of(org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE, TestConstants.SCOPE1);
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isNotSameAs(catalogSession);
          HTTPRequest actual = tableSession.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void tableSessionCacheHit() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1);
        Map<String, String> tableProperties =
            Map.of(
                Basic.SCOPE,
                TestConstants.SCOPE2,
                Basic.GRANT_TYPE,
                GrantType.TOKEN_EXCHANGE.name(),
                TokenExchange.SUBJECT_TOKEN,
                TestConstants.SUBJECT_TOKEN,
                TokenExchange.ACTOR_TOKEN,
                TestConstants.ACTOR_TOKEN);
        try (AuthSession catalogSession =
                manager.catalogSession(env.getHttpClient(), catalogProperties);
            AuthSession tableSession1 =
                manager.tableSession(table, tableProperties, catalogSession);
            AuthSession tableSession2 =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession1).isNotSameAs(catalogSession);
          assertThat(tableSession2).isNotSameAs(catalogSession);
          assertThat(tableSession1).isSameAs(tableSession2);
        }
      }
    }

    @Test
    void standaloneTableSession() {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> tableProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1,
                Basic.EXTRA_PARAMS_PREFIX + "extra1",
                "value1");
        try (AuthSession tableSession1 =
                manager.tableSession(env.getHttpClient(), tableProperties);
            AuthSession tableSession2 =
                manager.tableSession(env.getHttpClient(), tableProperties)) {
          assertThat(tableSession1).isSameAs(tableSession2);
          HTTPRequest actual1 = tableSession1.authenticate(request);
          assertThat(actual1.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
          HTTPRequest actual2 = tableSession2.authenticate(request);
          assertThat(actual2.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void close() {

      try (OAuth2Manager manager = new OAuth2Manager("test")) {
        manager.close();
        // should clear internal fields
        assertThat(manager).extracting("initSession").isNull();
        assertThat(manager).extracting("refreshExecutor").isNull();
        assertThat(manager).extracting("sessionCache").isNull();
        assertThat(manager).extracting("client").isNull();
      }

      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager =
              new OAuth2Manager(
                  "test",
                  (name, properties) ->
                      new AuthSessionCache<>(name, Duration.ofHours(1)) {
                        @Override
                        public OAuth2Session cachedSession(
                            OAuth2AgentSpec key, Function<OAuth2AgentSpec, OAuth2Session> loader) {
                          return super.cachedSession(key, k -> Mockito.spy(loader.apply(key)));
                        }
                      })) {

        Map<String, String> catalogProperties =
            Map.of(
                Basic.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                Basic.CLIENT_ID,
                TestConstants.CLIENT_ID1,
                Basic.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1,
                Basic.SCOPE,
                TestConstants.SCOPE1);

        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    Basic.CLIENT_ID,
                    TestConstants.CLIENT_ID2,
                    Basic.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2),
                Map.of(Basic.SCOPE, TestConstants.SCOPE2));

        Map<String, String> tableProperties = Map.of(Basic.SCOPE, TestConstants.SCOPE2);

        try (AuthSession initSession =
                Mockito.spy(manager.initSession(env.getHttpClient(), catalogProperties));
            AuthSession catalogSession =
                Mockito.spy(manager.catalogSession(env.getHttpClient(), catalogProperties));
            AuthSession contextSession = manager.contextualSession(context, catalogSession);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {

          manager.close();

          // init and catalog sessions should not be closed – it's the responsibility of the caller
          Mockito.verify(initSession, never()).close();
          Mockito.verify(catalogSession, never()).close();
          // context and table sessions should be evicted from cache and closed
          Mockito.verify(contextSession).close();
          Mockito.verify(tableSession).close();

          // should clear internal fields
          assertThat(manager).extracting("initSession").isNull();
          assertThat(manager).extracting("refreshExecutor").isNull();
          assertThat(manager).extracting("sessionCache").isNull();
          assertThat(manager).extracting("client").isNull();
        }
      }
    }
  }

  @Nested
  class CatalogTests {

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
                  // client id and secret from the catalog properties, scope from the table
                  // properties
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
                            (spec, session) ->
                                assertSpec(spec, CLIENT_ID2, CLIENT_SECRET2, SCOPE3)));
      }
    }

    private void assertSpec(
        OAuth2AgentSpec spec, String clientId, String clientSecret, String scope) {
      assertThat(spec).isNotNull();
      assertThat(spec.getBasicConfig().getClientId()).contains(clientId);
      assertThat(spec.getBasicConfig().getClientSecret()).contains(Secret.of(clientSecret));
      assertThat(spec.getBasicConfig().getScopes()).containsOnly(scope);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private InstanceOfAssertFactory<Cache, MapAssert<OAuth2AgentSpec, OAuth2Session>> asMap() {
      return new InstanceOfAssertFactory<Cache, MapAssert<OAuth2AgentSpec, OAuth2Session>>(
          Cache.class,
          new Class[] {OAuth2AgentSpec.class, OAuth2Session.class},
          actual -> Assertions.assertThat(actual.asMap()));
    }
  }
}

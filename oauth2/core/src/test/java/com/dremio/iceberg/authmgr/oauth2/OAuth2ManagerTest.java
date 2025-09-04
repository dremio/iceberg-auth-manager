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

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.mockito.Mockito.never;

import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCache;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.github.benmanes.caffeine.cache.Cache;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
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
import org.apache.iceberg.rest.auth.AuthSession;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactory;
import org.assertj.core.api.MapAssert;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
    void catalogSessionWithoutInit() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1",
                "value1");
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession session = manager.catalogSession(client, properties)) {
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
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1",
                "value1");
        try (HTTPClient httpClient = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession session = manager.initSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
        try (HTTPClient httpClient = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession session = manager.catalogSession(httpClient, properties)) {
          HTTPRequest actual = session.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void contextualSessionEmptyContext() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());
        SessionCatalog.SessionContext context = SessionCatalog.SessionContext.createEmpty();
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, properties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void contextualSessionIdenticalSpec() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> properties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());
        SessionCatalog.SessionContext context =
            new SessionCatalog.SessionContext(
                "test",
                "test",
                properties,
                Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE1.toString()));
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, properties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void contextualSessionDifferentSpec() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1",
                "value1");
        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    PREFIX + '.' + BasicConfig.CLIENT_ID,
                    TestConstants.CLIENT_ID2.getValue(),
                    PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2.getValue()),
                Map.of(
                    PREFIX + '.' + BasicConfig.SCOPE,
                    TestConstants.SCOPE2.toString(),
                    PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra2",
                    "value2"));
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
            AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession).isNotSameAs(catalogSession);
          HTTPRequest actual = contextualSession.authenticate(request);
          assertThat(actual.headers().entries("Authorization"))
              .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
        }
      }
    }

    @Test
    void contextualSessionCacheHit() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());
        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    PREFIX + '.' + BasicConfig.CLIENT_ID,
                    TestConstants.CLIENT_ID2.getValue(),
                    PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2.getValue(),
                    TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN,
                    TestConstants.SUBJECT_TOKEN.getValue(),
                    TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN,
                    TestConstants.ACTOR_TOKEN.getValue()),
                Map.of(
                    PREFIX + '.' + BasicConfig.GRANT_TYPE,
                    GrantType.TOKEN_EXCHANGE.getValue(),
                    PREFIX + '.' + BasicConfig.SCOPE,
                    TestConstants.SCOPE2.toString()));
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
            AuthSession contextualSession1 = manager.contextualSession(context, catalogSession);
            AuthSession contextualSession2 = manager.contextualSession(context, catalogSession)) {
          assertThat(contextualSession1).isNotSameAs(catalogSession);
          assertThat(contextualSession2).isNotSameAs(catalogSession);
          assertThat(contextualSession1).isSameAs(contextualSession2);
        }
      }
    }

    @Test
    void tableSessionEmptyConfig() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());
        Map<String, String> tableProperties = Map.of();
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void tableSessionIdenticalSpec() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());
        Map<String, String> tableProperties =
            Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE1.toString());
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
            AuthSession tableSession =
                manager.tableSession(table, tableProperties, catalogSession)) {
          assertThat(tableSession).isSameAs(catalogSession);
        }
      }
    }

    @Test
    void tableSessionDifferentSpec() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1",
                "value1");
        Map<String, String> tableProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE2.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra2",
                "value2");
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
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
    void tableSessionCacheHit() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue());
        Map<String, String> tableProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE2.toString(),
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.TOKEN_EXCHANGE.getValue(),
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN,
                TestConstants.SUBJECT_TOKEN.getValue(),
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN,
                TestConstants.ACTOR_TOKEN.getValue());
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession catalogSession = manager.catalogSession(client, catalogProperties);
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
    void standaloneTableSession() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager = new OAuth2Manager("test")) {
        Map<String, String> tableProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString(),
                PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1",
                "value1");
        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession tableSession1 = manager.tableSession(client, tableProperties);
            AuthSession tableSession2 = manager.tableSession(client, tableProperties)) {
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
    void close() throws IOException {

      try (OAuth2Manager manager = new OAuth2Manager("test")) {
        manager.close();
        // should clear internal fields
        assertThat(manager).extracting("initSession").isNull();
        assertThat(manager).extracting("refreshExecutor").isNull();
        assertThat(manager).extracting("sessionCache").isNull();
      }

      try (TestEnvironment env = TestEnvironment.builder().build();
          OAuth2Manager manager =
              new OAuth2Manager(
                  "test",
                  (name, properties) ->
                      new AuthSessionCache<>(name, Duration.ofHours(1)) {
                        @Override
                        public OAuth2Session cachedSession(
                            OAuth2Config key, Function<OAuth2Config, OAuth2Session> loader) {
                          return super.cachedSession(key, k -> Mockito.spy(loader.apply(key)));
                        }
                      })) {

        Map<String, String> catalogProperties =
            Map.of(
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                env.getTokenEndpoint().toString(),
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                TestConstants.CLIENT_ID1.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                TestConstants.CLIENT_SECRET1.getValue(),
                PREFIX + '.' + BasicConfig.SCOPE,
                TestConstants.SCOPE1.toString());

        SessionContext context =
            new SessionContext(
                "test",
                "test",
                Map.of(
                    PREFIX + '.' + BasicConfig.CLIENT_ID,
                    TestConstants.CLIENT_ID2.getValue(),
                    PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                    TestConstants.CLIENT_SECRET2.getValue()),
                Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE2.toString()));

        Map<String, String> tableProperties =
            Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE2.toString());

        try (HTTPClient client = env.newIcebergRestClientBuilder(Map.of()).build();
            AuthSession initSession = Mockito.spy(manager.initSession(client, catalogProperties));
            AuthSession catalogSession =
                Mockito.spy(manager.catalogSession(client, catalogProperties));
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
        }
      }
    }
  }

  @Nested
  class CatalogTests {

    private static final String SESSION_CACHE =
        "sessionCatalog.authManager.sessionCache.sessionCache";
    private static final String CATALOG_CONFIG = "sessionCatalog.catalogAuth.config";

    @Test
    void testCatalogProperties() throws IOException {
      try (TestEnvironment env = TestEnvironment.builder().build();
          RESTCatalog catalog = env.newCatalog()) {
        Table table = catalog.loadTable(TestConstants.TABLE_IDENTIFIER);
        assertThat(table).isNotNull();
        assertThat(table.name()).isEqualTo(catalog.name() + "." + TestConstants.TABLE_IDENTIFIER);
        assertThat(catalog)
            .extracting(CATALOG_CONFIG, type(OAuth2Config.class))
            .satisfies(
                spec ->
                    assertConfig(
                        spec,
                        TestConstants.CLIENT_ID1,
                        TestConstants.CLIENT_SECRET1,
                        TestConstants.SCOPE1));
        assertThat(catalog).extracting(SESSION_CACHE).isNull();
      }
    }

    @Test
    void testCatalogAndSessionProperties() throws IOException {
      try (TestEnvironment env =
              TestEnvironment.builder().sessionContext(TestConstants.SESSION_CONTEXT).build();
          RESTCatalog catalog = env.newCatalog()) {
        Table table = catalog.loadTable(TestConstants.TABLE_IDENTIFIER);
        assertThat(table).isNotNull();
        assertThat(table.name()).isEqualTo(catalog.name() + "." + TestConstants.TABLE_IDENTIFIER);
        assertThat(catalog)
            .extracting(CATALOG_CONFIG, type(OAuth2Config.class))
            .satisfies(
                spec ->
                    assertConfig(
                        spec,
                        TestConstants.CLIENT_ID1,
                        TestConstants.CLIENT_SECRET1,
                        TestConstants.SCOPE1));
        assertThat(catalog)
            .extracting(SESSION_CACHE, asMap())
            .satisfies(
                cache -> {
                  assertThat(cache).hasSize(1);
                  OAuth2Config spec = cache.keySet().iterator().next();
                  assertConfig(
                      spec,
                      TestConstants.CLIENT_ID2,
                      TestConstants.CLIENT_SECRET2,
                      TestConstants.SCOPE2);
                });
      }
    }

    @Test
    void testCatalogAndTableProperties() throws IOException {
      try (TestEnvironment env =
              TestEnvironment.builder()
                  .tableProperties(
                      Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE2.toString()))
                  .build();
          RESTCatalog catalog = env.newCatalog()) {
        Table table = catalog.loadTable(TestConstants.TABLE_IDENTIFIER);
        assertThat(table).isNotNull();
        assertThat(table.name()).isEqualTo(catalog.name() + "." + TestConstants.TABLE_IDENTIFIER);
        assertThat(catalog)
            .extracting(CATALOG_CONFIG, type(OAuth2Config.class))
            .satisfies(
                spec ->
                    assertConfig(
                        spec,
                        TestConstants.CLIENT_ID1,
                        TestConstants.CLIENT_SECRET1,
                        TestConstants.SCOPE1));
        assertThat(catalog)
            .extracting(SESSION_CACHE, asMap())
            .satisfies(
                cache -> {
                  assertThat(cache).hasSize(1);
                  OAuth2Config spec = cache.keySet().iterator().next();
                  // client id and secret from the catalog properties, scope from the table
                  // properties
                  assertConfig(
                      spec,
                      TestConstants.CLIENT_ID1,
                      TestConstants.CLIENT_SECRET1,
                      TestConstants.SCOPE2);
                });
      }
    }

    @Test
    void testCatalogAndSessionAndTableProperties() throws IOException {
      try (TestEnvironment env =
              TestEnvironment.builder()
                  .sessionContext(TestConstants.SESSION_CONTEXT)
                  .tableProperties(
                      Map.of(PREFIX + '.' + BasicConfig.SCOPE, TestConstants.SCOPE3.toString()))
                  .build();
          RESTCatalog catalog = env.newCatalog()) {
        Table table = catalog.loadTable(TestConstants.TABLE_IDENTIFIER);
        assertThat(table).isNotNull();
        assertThat(table.name()).isEqualTo(catalog.name() + "." + TestConstants.TABLE_IDENTIFIER);
        assertThat(catalog)
            .extracting(CATALOG_CONFIG, type(OAuth2Config.class))
            .satisfies(
                spec ->
                    assertConfig(
                        spec,
                        TestConstants.CLIENT_ID1,
                        TestConstants.CLIENT_SECRET1,
                        TestConstants.SCOPE1));
        assertThat(catalog)
            .extracting(SESSION_CACHE, asMap())
            .satisfies(
                cache ->
                    assertThat(cache)
                        .hasSize(2)
                        // context session
                        .anySatisfy(
                            (spec, session) ->
                                assertConfig(
                                    spec,
                                    TestConstants.CLIENT_ID2,
                                    TestConstants.CLIENT_SECRET2,
                                    TestConstants.SCOPE2))
                        // table session
                        // client id and secret from the context session, scope from the table
                        // properties
                        .anySatisfy(
                            (spec, session) ->
                                assertConfig(
                                    spec,
                                    TestConstants.CLIENT_ID2,
                                    TestConstants.CLIENT_SECRET2,
                                    TestConstants.SCOPE3)));
      }
    }

    private void assertConfig(
        OAuth2Config config, ClientID clientId, Secret clientSecret, Scope scope) {
      assertThat(config).isNotNull();
      assertThat(config.getBasicConfig().getClientId()).contains(clientId);
      assertThat(config.getBasicConfig().getClientSecret()).contains(clientSecret);
      assertThat(config.getBasicConfig().getScope()).contains(scope);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private InstanceOfAssertFactory<Cache, MapAssert<OAuth2Config, OAuth2Session>> asMap() {
      return new InstanceOfAssertFactory<Cache, MapAssert<OAuth2Config, OAuth2Session>>(
          Cache.class,
          new Class[] {OAuth2Config.class, OAuth2Session.class},
          actual -> Assertions.assertThat(actual.asMap()));
    }
  }
}

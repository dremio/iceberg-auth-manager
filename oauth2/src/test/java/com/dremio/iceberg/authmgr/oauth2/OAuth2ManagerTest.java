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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.cache.AuthSessionCache;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;
import org.apache.iceberg.catalog.SessionCatalog;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.rest.HTTPHeaders.HTTPHeader;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.HTTPRequest.HTTPMethod;
import org.apache.iceberg.rest.ImmutableHTTPRequest;
import org.apache.iceberg.rest.auth.AuthSession;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class OAuth2ManagerTest {

  public static final TableIdentifier TABLE = TableIdentifier.of("t1");
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
              TestConstants.SCOPE1);
      try (AuthSession session = manager.catalogSession(env.getHttpClient(), properties)) {
        HTTPRequest actual = session.authenticate(request);
        assertThat(actual.headers().entries("Authorization"))
            .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
      }
    }
  }

  @Test
  void catalogSessionWithInit() {
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
      try (AuthSession session = manager.initSession(env.getHttpClient(), properties)) {
        HTTPRequest actual = session.authenticate(request);
        assertThat(actual.headers().entries("Authorization"))
            .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial"));
      }
      try (AuthSession session = manager.catalogSession(env.getHttpClient(), properties)) {
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
      try (AuthSession catalogSession =
              manager.catalogSession(env.getHttpClient(), catalogProperties);
          AuthSession contextualSession = manager.contextualSession(context, catalogSession)) {
        assertThat(contextualSession).isNotSameAs(catalogSession);
        HTTPRequest actual = contextualSession.authenticate(request);
        assertThat(actual.headers().entries("Authorization"))
            .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial2"));
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
              TestConstants.SCOPE1);
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
            .containsOnly(HTTPHeader.of("Authorization", "Bearer access_initial2"));
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
                  TestConstants.CLIENT_SECRET2),
              Map.of(Basic.SCOPE, TestConstants.SCOPE2));
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
          AuthSession tableSession = manager.tableSession(TABLE, tableProperties, catalogSession)) {
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
          AuthSession tableSession = manager.tableSession(TABLE, tableProperties, catalogSession)) {
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
              TestConstants.CLIENT_SECRET1);
      Map<String, String> tableProperties = Map.of(Basic.SCOPE, TestConstants.SCOPE1);
      try (AuthSession catalogSession =
              manager.catalogSession(env.getHttpClient(), catalogProperties);
          AuthSession tableSession = manager.tableSession(TABLE, tableProperties, catalogSession)) {
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
              TestConstants.CLIENT_SECRET1);
      Map<String, String> tableProperties =
          Map.of(org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE, TestConstants.SCOPE1);
      try (AuthSession catalogSession =
              manager.catalogSession(env.getHttpClient(), catalogProperties);
          AuthSession tableSession = manager.tableSession(TABLE, tableProperties, catalogSession)) {
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
          Map.of(org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE, TestConstants.SCOPE2);
      try (AuthSession catalogSession =
              manager.catalogSession(env.getHttpClient(), catalogProperties);
          AuthSession tableSession1 = manager.tableSession(TABLE, tableProperties, catalogSession);
          AuthSession tableSession2 =
              manager.tableSession(TABLE, tableProperties, catalogSession)) {
        assertThat(tableSession1).isNotSameAs(catalogSession);
        assertThat(tableSession2).isNotSameAs(catalogSession);
        assertThat(tableSession1).isSameAs(tableSession2);
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

      Map<String, String> tableProperties =
          Map.of(org.apache.iceberg.rest.auth.OAuth2Properties.SCOPE, TestConstants.SCOPE2);

      try (AuthSession initSession =
              Mockito.spy(manager.initSession(env.getHttpClient(), catalogProperties));
          AuthSession catalogSession =
              Mockito.spy(manager.catalogSession(env.getHttpClient(), catalogProperties));
          AuthSession contextSession = manager.contextualSession(context, catalogSession);
          AuthSession tableSession = manager.tableSession(TABLE, tableProperties, catalogSession)) {

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

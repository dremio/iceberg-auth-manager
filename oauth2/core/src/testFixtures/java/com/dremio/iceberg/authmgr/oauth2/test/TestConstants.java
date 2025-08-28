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
package com.dremio.iceberg.authmgr.oauth2.test;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.apache.iceberg.catalog.SessionCatalog;
import org.apache.iceberg.catalog.TableIdentifier;

public class TestConstants {

  public static final ClientID CLIENT_ID1 = new ClientID("Client1");
  public static final ClientID CLIENT_ID2 = new ClientID("Client2");
  public static final ClientID CLIENT_ID3 = new ClientID("Client3");
  public static final ClientID CLIENT_ID4 = new ClientID("Client4");

  public static final Secret CLIENT_SECRET1 = new Secret("s3cr3t");
  public static final Secret CLIENT_SECRET2 = new Secret("sEcrEt");
  public static final Secret CLIENT_SECRET3 = new Secret(Strings.repeat("S3CR3T", 10));

  public static final String USERNAME = "Alice";
  public static final Secret PASSWORD = new Secret("s3cr3t");

  public static final Scope SCOPE1 = new Scope("catalog");
  public static final Scope SCOPE2 = new Scope("session");
  public static final Scope SCOPE3 = new Scope("table");

  public static final String CLIENT_CREDENTIALS1_BASE_64 =
      Base64.getEncoder()
          .encodeToString(
              (CLIENT_ID1.getValue() + ":" + CLIENT_SECRET1.getValue())
                  .getBytes(StandardCharsets.UTF_8));

  public static final String CLIENT_CREDENTIALS2_BASE_64 =
      Base64.getEncoder()
          .encodeToString(
              (CLIENT_ID2.getValue() + ":" + CLIENT_SECRET2.getValue())
                  .getBytes(StandardCharsets.UTF_8));

  public static final Instant NOW = Instant.parse("2025-01-01T00:00:00Z");

  public static final int ACCESS_TOKEN_EXPIRES_IN_SECONDS = 3600;

  public static final Instant ACCESS_TOKEN_EXPIRATION_TIME =
      NOW.plusSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);

  public static final Duration ACCESS_TOKEN_LIFESPAN =
      Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);

  public static final int REFRESH_TOKEN_EXPIRES_IN_SECONDS = 86400;

  public static final Instant REFRESH_TOKEN_EXPIRATION_TIME =
      NOW.plusSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);

  public static final Duration REFRESH_TOKEN_LIFESPAN =
      Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);

  public static final TypelessAccessToken SUBJECT_TOKEN = new TypelessAccessToken("subject");
  public static final TypelessAccessToken ACTOR_TOKEN = new TypelessAccessToken("actor");

  public static final Audience AUDIENCE = new Audience("audience");
  public static final URI RESOURCE = URI.create("urn:authmgr:test:resource");

  public static final TokenTypeURI SUBJECT_TOKEN_TYPE = TokenTypeURI.ACCESS_TOKEN;
  public static final TokenTypeURI ACTOR_TOKEN_TYPE = TokenTypeURI.ACCESS_TOKEN;
  public static final TokenTypeURI REQUESTED_TOKEN_TYPE = TokenTypeURI.ACCESS_TOKEN;

  public static final String WAREHOUSE = "warehouse1";
  public static final TableIdentifier TABLE_IDENTIFIER = TableIdentifier.of("namespace1", "table1");

  public static final SessionCatalog.SessionContext SESSION_CONTEXT =
      new SessionCatalog.SessionContext(
          UUID.randomUUID().toString(),
          "user",
          Map.of(
              Basic.CLIENT_ID,
              TestConstants.CLIENT_ID2.getValue(),
              Basic.CLIENT_SECRET,
              TestConstants.CLIENT_SECRET2.getValue()),
          Map.of(Basic.SCOPE, TestConstants.SCOPE2.toString()));

  private TestConstants() {}
}

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
package com.dremio.iceberg.authmgr.oauth2.test;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.Basic;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
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

  public static final String CLIENT_ID1 = "Client1";
  public static final String CLIENT_ID2 = "Client2";
  public static final String CLIENT_SECRET1 = "s3cr3t";
  public static final String CLIENT_SECRET2 = "sEcrEt";

  public static final String USERNAME = "Alice";
  public static final String PASSWORD = "s3cr3t";

  public static final String SCOPE1 = "catalog";
  public static final String SCOPE2 = "session";
  public static final String SCOPE3 = "table";

  public static final String AUTHORIZATION_CODE = "CAFE-BABE";

  public static final String USER_CODE = "CAFE-BABE";
  public static final String DEVICE_CODE = "XYZ-123";

  public static final String CLIENT_CREDENTIALS1_BASE_64 =
      Base64.getEncoder()
          .encodeToString((CLIENT_ID1 + ":" + CLIENT_SECRET1).getBytes(StandardCharsets.UTF_8));
  public static final String CLIENT_CREDENTIALS2_BASE_64 =
      Base64.getEncoder()
          .encodeToString((CLIENT_ID2 + ":" + CLIENT_SECRET2).getBytes(StandardCharsets.UTF_8));

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

  public static final String SUBJECT_TOKEN = "subject";
  public static final String ACTOR_TOKEN = "actor";
  public static final String AUDIENCE = "audience";

  public static final URI SUBJECT_TOKEN_TYPE = TypedToken.URN_ACCESS_TOKEN;
  public static final URI ACTOR_TOKEN_TYPE = TypedToken.URN_ID_TOKEN;
  public static final URI REQUESTED_TOKEN_TYPE = TypedToken.URN_ACCESS_TOKEN;
  public static final URI RESOURCE = URI.create("urn:authmgr:test:resource");

  public static final String WAREHOUSE = "warehouse1";
  public static final TableIdentifier TABLE_IDENTIFIER = TableIdentifier.of("namespace1", "table1");

  public static final SessionCatalog.SessionContext SESSION_CONTEXT =
      new SessionCatalog.SessionContext(
          UUID.randomUUID().toString(),
          "user",
          Map.of(
              Basic.CLIENT_ID,
              TestConstants.CLIENT_ID2,
              Basic.CLIENT_SECRET,
              TestConstants.CLIENT_SECRET2),
          Map.of(Basic.SCOPE, TestConstants.SCOPE2));

  private TestConstants() {}
}

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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;

import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import org.junit.jupiter.api.Test;

class IcebergRefreshTokenFlowTest {

  private final Tokens currentTokens =
      Tokens.of(AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME), null);

  @Test
  void fetchNewTokens() {
    try (TestEnvironment env = TestEnvironment.builder().dialect(Dialect.ICEBERG_REST).build();
        Flow flow = env.newTokenRefreshFlow()) {
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertTokens(tokens, "access_refreshed", null);
    }
  }

  @Test
  void fetchNewTokensBearerAuth() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dialect(Dialect.ICEBERG_REST)
                .token("access_initial")
                .build();
        Flow flow = env.newTokenRefreshFlow()) {
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertTokens(tokens, "access_refreshed", null);
    }
  }
}

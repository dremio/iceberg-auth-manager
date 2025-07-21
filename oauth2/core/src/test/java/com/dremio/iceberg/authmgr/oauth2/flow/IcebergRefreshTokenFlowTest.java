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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;

import com.dremio.iceberg.authmgr.oauth2.config.Dialect;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;

class IcebergRefreshTokenFlowTest {

  private final Tokens currentTokens =
      Tokens.of(AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME), null);

  @Test
  void fetchNewTokens() throws InterruptedException, ExecutionException {
    try (TestEnvironment env = TestEnvironment.builder().dialect(Dialect.ICEBERG_REST).build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      RefreshFlow flow = flowFactory.createTokenRefreshFlow();
      Tokens tokens = flow.refreshTokens(currentTokens).toCompletableFuture().get();
      assertTokens(tokens, "access_refreshed", null);
    }
  }

  @Test
  void fetchNewTokensBearerAuth() throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .dialect(Dialect.ICEBERG_REST)
                .token("access_initial")
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      RefreshFlow flow = flowFactory.createTokenRefreshFlow();
      Tokens tokens = flow.refreshTokens(currentTokens).toCompletableFuture().get();
      assertTokens(tokens, "access_refreshed", null);
    }
  }
}

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

import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;

import com.dremio.iceberg.authmgr.oauth2.config.PkceTransformation;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AuthorizationCodeFlowTest {

  @ParameterizedTest
  @CsvSource({
    "true, S256, true, true",
    "true, S256, true, false",
    "true, S256, false, true",
    "true, S256, false, false",
    "true, PLAIN, true, true",
    "true, PLAIN, true, false",
    "true, PLAIN, false, true",
    "true, PLAIN, false, false",
    "false, S256, true, true",
    "false, S256, true, false",
    "false, S256, false, true",
    "false, S256, false, false",
  })
  void fetchNewTokens(
      boolean pkceEnabled,
      PkceTransformation pkceTransformation,
      boolean privateClient,
      boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .pkceEnabled(pkceEnabled)
                .pkceTransformation(pkceTransformation)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      InitialFlow flow = flowFactory.createInitialFlow();
      Tokens tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokens(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }
}

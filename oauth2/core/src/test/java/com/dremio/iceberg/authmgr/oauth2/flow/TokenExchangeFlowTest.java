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

import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokensResult;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.nimbusds.oauth2.sdk.GrantType;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TokenExchangeFlowTest {

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void fetchNewTokens(boolean privateClient, boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(TokenExchangeFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }

  @ParameterizedTest
  @CsvSource({
    "true,  false, client_credentials                           , client_credentials",
    "true,  true,  password                                     , password",
    "true,  false, password                                     , password",
    "false, true,  password                                     , password",
    "false, false, password                                     , password",
    "true,  true,  authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "true,  false, authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "false, true,  authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "false, false, authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "true,  true,  urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "true,  false, urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "false, true,  urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "false, false, urn:ietf:params:oauth:grant-type:device_code , authorization_code",
  })
  void fetchNewTokensDynamic(
      boolean privateClient,
      boolean returnRefreshTokens,
      GrantType subjectGrantType,
      GrantType actorGrantType)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .privateClient(privateClient)
                // increase concurrency so that token fetches can happen in parallel
                .executorPoolSize(3)
                .returnRefreshTokens(returnRefreshTokens)
                .subjectToken(null)
                .subjectGrantType(subjectGrantType)
                .actorToken(null)
                .actorGrantType(actorGrantType)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(TokenExchangeFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }
}

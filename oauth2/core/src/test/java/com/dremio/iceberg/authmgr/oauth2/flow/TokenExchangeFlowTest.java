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
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TokenExchangeFlowTest {

  @ParameterizedTest
  @CsvSource({
    "client_secret_basic , true",
    "client_secret_basic , false",
    "client_secret_post  , true",
    "client_secret_post  , false",
    "none                , true",
    "none                , false",
  })
  void fetchNewTokens(ClientAuthenticationMethod authenticationMethod, boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .clientAuthenticationMethod(authenticationMethod)
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
    "client_secret_basic, false, client_credentials                           , client_credentials",
    "client_secret_basic, true,  password                                     , password",
    "client_secret_post , false, password                                     , password",
    "none               , true,  password                                     , password",
    "none               , false, password                                     , password",
    "client_secret_basic, true,  authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "client_secret_basic, false, authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "client_secret_post , true,  authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "none               , false, authorization_code                           , urn:ietf:params:oauth:grant-type:device_code",
    "client_secret_basic, true,  urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "client_secret_basic, false, urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "client_secret_post , true,  urn:ietf:params:oauth:grant-type:device_code , authorization_code",
    "none               , false, urn:ietf:params:oauth:grant-type:device_code , authorization_code",
  })
  void fetchNewTokensDynamic(
      ClientAuthenticationMethod authenticationMethod,
      boolean returnRefreshTokens,
      GrantType subjectGrantType,
      GrantType actorGrantType)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .clientAuthenticationMethod(authenticationMethod)
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

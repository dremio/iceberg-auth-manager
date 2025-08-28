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
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class RefreshTokenFlowTest {

  @ParameterizedTest
  @CsvSource({
    "client_secret_basic , true  , true",
    "client_secret_basic , true  , false",
    "client_secret_basic , false , false",
    "client_secret_post  , true  , true",
    "client_secret_post  , true  , false",
    "client_secret_post  , false , false",
    "none                , true  , true",
    "none                , true  , false",
    "none                , false , false",
  })
  void fetchNewTokens(
      ClientAuthenticationMethod authenticationMethod,
      boolean returnRefreshTokens,
      boolean returnRefreshTokenLifespan)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .returnRefreshTokenLifespan(returnRefreshTokenLifespan)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createTokenRefreshFlow(new RefreshToken("refresh_initial"));
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertThat(flow).isInstanceOf(RefreshTokenFlow.class);
      assertTokensResult(
          tokens,
          "access_refreshed",
          returnRefreshTokens ? "refresh_refreshed" : "refresh_initial",
          returnRefreshTokenLifespan);
    }
  }
}

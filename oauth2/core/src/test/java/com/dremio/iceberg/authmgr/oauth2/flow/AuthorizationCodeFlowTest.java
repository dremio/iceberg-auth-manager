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
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AuthorizationCodeFlowTest {

  @ParameterizedTest
  @CsvSource({
    "client_secret_basic, true,  S256,  true",
    "none               , true,  S256,  true",
    "client_secret_post , true,  S256,  false",
    "none               , true,  S256,  false",
    "client_secret_basic, true,  plain, true",
    "none               , true,  plain, true",
    "client_secret_post , true,  plain, false",
    "none               , true,  plain, false",
    "client_secret_basic, false, S256,  true",
    "none               , false, S256,  true",
    "client_secret_post , false, S256,  false",
    "none               , false, S256,  false",
  })
  void fetchNewTokens(
      ClientAuthenticationMethod authenticationMethod,
      boolean pkceEnabled,
      CodeChallengeMethod codeChallengeMethod,
      boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(authenticationMethod)
                .pkceEnabled(pkceEnabled)
                .codeChallengeMethod(codeChallengeMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(AuthorizationCodeFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }
}

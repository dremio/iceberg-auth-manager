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
package com.dremio.oauth2.agent.flow;

import static com.dremio.oauth2.agent.TestConstants.ACCESS_TOKEN_INITIAL;
import static com.dremio.oauth2.agent.TokenAssertions.assertTokensResult;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.oauth2.agent.ImmutableTestEnvironment;
import com.dremio.oauth2.agent.TestEnvironment;
import com.dremio.oauth2.agent.junit.EnumLike;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.util.concurrent.ExecutionException;
import org.junitpioneer.jupiter.cartesian.CartesianTest;

class ClientCredentialsFlowTest {

  @CartesianTest
  void fetchNewTokens(@EnumLike(excludes = "none") ClientAuthenticationMethod authenticationMethod)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            ImmutableTestEnvironment.builder()
                .clientAuthenticationMethod(authenticationMethod)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(ClientCredentialsFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, ACCESS_TOKEN_INITIAL, null);
    }
  }
}

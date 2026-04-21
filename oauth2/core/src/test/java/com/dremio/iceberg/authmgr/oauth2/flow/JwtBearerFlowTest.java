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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokensResult;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.EnumLike;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;

class JwtBearerFlowTest {

  @CartesianTest
  void fetchNewTokens(
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(JwtBearerFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
    }
  }

  @CartesianTest
  void fetchNewTokensDynamic(
      @EnumLike(excludes = {"none", "client_secret_basic"})
          ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens,
      @EnumLike(
              excludes = {
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "urn:ietf:params:oauth:grant-type:token-exchange"
              })
          GrantType assertionGrantType)
      throws InterruptedException, ExecutionException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .clientAuthenticationMethod(authenticationMethod)
                .executorPoolSize(2)
                .returnRefreshTokens(returnRefreshTokens)
                .assertion(null)
                .assertionGrantType(assertionGrantType)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(JwtBearerFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
    }
  }

  @Test
  void fetchNewTokensInvalidAssertion() {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.JWT_BEARER)
                .assertion("InvalidJWT")
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(JwtBearerFlow.class);
      assertThat(flow.fetchNewTokens())
          .completesExceptionallyWithin(Duration.ofSeconds(30))
          .withThrowableOfType(ExecutionException.class)
          .withCauseInstanceOf(IllegalArgumentException.class)
          .withRootCauseInstanceOf(ParseException.class)
          .withMessageContaining("Failed to create JWT Bearer grant")
          .withMessageContaining("The assertion is not a JWT");
    }
  }
}

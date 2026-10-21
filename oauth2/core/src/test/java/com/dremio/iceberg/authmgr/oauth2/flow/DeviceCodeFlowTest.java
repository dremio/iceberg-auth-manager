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
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.UserCode;
import java.net.URI;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.junitpioneer.jupiter.cartesian.CartesianTest.Values;

class DeviceCodeFlowTest {

  @CartesianTest
  void fetchNewTokens(
      @EnumLike ClientAuthenticationMethod authenticationMethod,
      @Values(booleans = {true, false}) boolean returnRefreshTokens)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .clientAuthenticationMethod(authenticationMethod)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(DeviceCodeFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(
          tokens, ACCESS_TOKEN_INITIAL, returnRefreshTokens ? REFRESH_TOKEN_INITIAL : null);
    }
  }

  private static final URI VERIFICATION_URI = URI.create("https://example.com/device");
  private static final URI VERIFICATION_URI_COMPLETE =
      URI.create("https://example.com/device?user_code=ABCD-EFGH");

  private static DeviceAuthorizationSuccessResponse response(URI verificationUriComplete) {
    return new DeviceAuthorizationSuccessResponse(
        new DeviceCode("device-code"),
        new UserCode("ABCD-EFGH"),
        VERIFICATION_URI,
        verificationUriComplete,
        300,
        5,
        null);
  }

  @Test
  void formatInstructionsSeparateByDefault() {
    assertThat(
            DeviceCodeFlow.formatInstructions(
                "[prefix] ", response(VERIFICATION_URI_COMPLETE), false))
        .containsExactly(
            "[prefix] Please open the following URL to continue:",
            "[prefix] https://example.com/device",
            "[prefix] And enter the code:",
            "[prefix] ABCD-EFGH");
  }

  @Test
  void formatInstructionsCompleteUri() {
    assertThat(
            DeviceCodeFlow.formatInstructions(
                "[prefix] ", response(VERIFICATION_URI_COMPLETE), true))
        .containsExactly(
            "[prefix] Please open the following URL to continue:",
            "[prefix] https://example.com/device?user_code=ABCD-EFGH");
  }

  @Test
  void formatInstructionsCompleteUriRequestedButNotReturned() {
    List<String> lines = DeviceCodeFlow.formatInstructions("[prefix] ", response(null), true);
    assertThat(lines)
        .containsExactly(
            "[prefix] Please open the following URL to continue:",
            "[prefix] https://example.com/device",
            "[prefix] And enter the code:",
            "[prefix] ABCD-EFGH");
  }
}

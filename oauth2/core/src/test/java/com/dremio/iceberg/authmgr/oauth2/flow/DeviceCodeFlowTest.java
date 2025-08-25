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

import com.dremio.iceberg.authmgr.oauth2.config.DeviceCodeConfig;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.nimbusds.oauth2.sdk.GrantType;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class DeviceCodeFlowTest {

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void fetchNewTokens(boolean privateClient, boolean returnRefreshTokens)
      throws ExecutionException, InterruptedException {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.DEVICE_CODE)
                .deviceCodeConfig(
                    DeviceCodeConfig.builder()
                        .minPollInterval(Duration.ofMillis(10))
                        .pollInterval(Duration.ofMillis(10))
                        .ignoreServerPollInterval(true)
                        .build())
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(DeviceCodeFlow.class);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, "access_initial", returnRefreshTokens ? "refresh_initial" : null);
    }
  }
}

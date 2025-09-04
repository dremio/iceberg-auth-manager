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
package com.dremio.iceberg.authmgr.oauth2.tokenexchange;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SoftAssertionsExtension.class)
class SubjectTokenSupplierTest {

  private static final Map<String, String> CONFIG =
      Map.of(BasicConfig.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.getValue());

  @Test
  void testSupplyTokenAsyncStatic() {
    OAuth2Config config = createMainConfig("subject-token", TokenTypeURI.ID_TOKEN, Map.of());
    try (SubjectTokenSupplier supplier = createSupplier(config)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage)
          .isCompletedWithValue(
              new BearerAccessToken("subject-token", 0, null, TokenTypeURI.ID_TOKEN));
    }
  }

  @Test
  void testSupplyTokenAsyncDynamic() {
    OAuth2Config config = createMainConfig(null, TokenTypeURI.ACCESS_TOKEN, CONFIG);
    try (SubjectTokenSupplier supplier = createSupplier(config)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isNotCompleted();
    }
  }

  @Test
  @SuppressWarnings("resource")
  void testValidate() {
    OAuth2Config config = createMainConfig(null, TokenTypeURI.ACCESS_TOKEN, Map.of());
    assertThatIllegalArgumentException()
        .isThrownBy(() -> createSupplier(config))
        .withMessage("Subject token is dynamic but no configuration is provided");
  }

  private static OAuth2Config createMainConfig(
      String subjectToken, TokenTypeURI subjectTokenType, Map<String, String> subjectTokenConfig) {

    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();

    builder.put(PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.TOKEN_EXCHANGE.getValue());
    builder.put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_ID, "test-client");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "test-secret");

    builder.put(
        TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN_TYPE,
        subjectTokenType.getURI().toString());

    subjectTokenConfig.forEach(
        (k, v) ->
            builder.put(
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN + '.' + k, v));

    if (subjectToken != null) {
      builder.put(
          TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN, subjectToken);
    }

    return OAuth2Config.from(builder.build());
  }

  private static SubjectTokenSupplier createSupplier(OAuth2Config config) {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    return SubjectTokenSupplier.create(config, OAuth2AgentRuntime.of(executor));
  }
}

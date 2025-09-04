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
class ActorTokenSupplierTest {

  private static final Map<String, String> CONFIG =
      Map.of(BasicConfig.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.getValue());

  @Test
  void testSupplyActorTokenAsyncStatic() {
    OAuth2Config config = createMainConfig("actor-token", TokenTypeURI.ID_TOKEN, Map.of());
    try (ActorTokenSupplier supplier = createSupplier(config)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage)
          .isCompletedWithValue(
              new BearerAccessToken("actor-token", 0, null, TokenTypeURI.ID_TOKEN));
    }
  }

  @Test
  void testSupplyActorTokenAsyncDynamic() {
    OAuth2Config config = createMainConfig(null, TokenTypeURI.ACCESS_TOKEN, CONFIG);
    try (ActorTokenSupplier supplier = createSupplier(config)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isNotCompleted();
    }
  }

  @Test
  void testSupplyActorTokenAsyncNull() {
    OAuth2Config config = createMainConfig(null, TokenTypeURI.ACCESS_TOKEN, Map.of());
    try (ActorTokenSupplier supplier = createSupplier(config)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isCompletedWithValue(null);
    }
  }

  private static OAuth2Config createMainConfig(
      String actorToken, TokenTypeURI actorTokenType, Map<String, String> actorTokenConfig) {

    ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();

    builder.put(PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.TOKEN_EXCHANGE.getValue());
    builder.put(PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_ID, "test-client");
    builder.put(PREFIX + '.' + BasicConfig.CLIENT_SECRET, "test-secret");

    builder.put(
        TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.SUBJECT_TOKEN, "subject-token");
    builder.put(
        TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN_TYPE,
        actorTokenType.getURI().toString());

    actorTokenConfig.forEach(
        (k, v) ->
            builder.put(
                TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN + '.' + k, v));

    if (actorToken != null) {
      builder.put(TokenExchangeConfig.PREFIX + '.' + TokenExchangeConfig.ACTOR_TOKEN, actorToken);
    }

    return OAuth2Config.from(builder.build());
  }

  private static ActorTokenSupplier createSupplier(OAuth2Config config) {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    return ActorTokenSupplier.create(config, OAuth2AgentRuntime.of(executor));
  }
}
